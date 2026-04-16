/*
 * CRISP
 *
 * Single-phase varint build: fastest merge, no encode/decode tax
 * Walk: DFS with full frontier oracle, solutions streamed to disk
 *
 * Compile: gcc -O3 -march=native -o crisp crisp_tree.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
typedef uint64_t u64; typedef int64_t i64; typedef uint8_t u8; typedef uint32_t u32;
typedef unsigned __int128 u128;
static double now_ms(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1000.0+ts.tv_nsec/1e6;}

static u64 mem_peak=0;
static u64 mem_peak_vsize=0;
typedef struct { u64 rss; u64 vsize; u64 vpeak; u64 hwm; } MemInfo;
static MemInfo proc_mem(void){
    MemInfo m={0,0,0,0};
    FILE*f=fopen("/proc/self/status","r");if(!f)return m;
    char buf[256];
    while(fgets(buf,sizeof(buf),f)){
        if(!strncmp(buf,"VmRSS:",6))       m.rss  =(u64)atoll(buf+6)*1024;
        else if(!strncmp(buf,"VmSize:",7)) m.vsize=(u64)atoll(buf+7)*1024;
        else if(!strncmp(buf,"VmPeak:",7)) m.vpeak=(u64)atoll(buf+7)*1024;
        else if(!strncmp(buf,"VmHWM:",6))  m.hwm  =(u64)atoll(buf+6)*1024;
    }
    fclose(f);
    /* Fall back to our own tracking if the kernel doesn't expose VmPeak/VmHWM */
    if(m.rss > mem_peak)        mem_peak       = m.rss;
    if(m.vsize > mem_peak_vsize) mem_peak_vsize = m.vsize;
    if(m.vpeak == 0) m.vpeak = mem_peak_vsize;
    if(m.hwm == 0)   m.hwm   = mem_peak;
    return m;
}
static u64 proc_rss(void){return proc_mem().rss;}
static void mem_track(u64 bytes){(void)bytes;(void)proc_mem();}
static const char* fmt_bytes(u64 b,char*s){
    if(b<1024)sprintf(s,"%lluB",(unsigned long long)b);
    else if(b<1024*1024)sprintf(s,"%.1fKB",b/1024.0);
    else if(b<1024ULL*1024*1024)sprintf(s,"%.1fMB",b/(1024.0*1024));
    else sprintf(s,"%.2fGB",b/(1024.0*1024*1024));
    return s;
}

static inline int vw(u8*b,u64 v){int i=0;while(v>=128){b[i++]=(v&0x7F)|0x80;v>>=7;}b[i++]=(u8)v;return i;}
static inline u64 vr64(const u8*b,u64*p){u64 v=0;int s=0;while(b[*p]&0x80){v|=(u64)(b[*p]&0x7F)<<s;s+=7;(*p)++;}v|=(u64)b[*p]<<s;(*p)++;return v;}

#define RC_TOP (1ULL << 48)
typedef struct { u64 low, range; u8 *buf; u64 pos, cap; } RCEnc;
static RCEnc rce_new(u64 cap){RCEnc e;e.buf=calloc(cap,1);e.cap=cap;e.pos=0;e.low=0;e.range=~(u64)0;return e;}
static void rce_grow(RCEnc*e){e->cap*=2;e->buf=realloc(e->buf,e->cap);if(!e->buf){fprintf(stderr,"[FATAL]\n");exit(1);}}
static void rce_norm(RCEnc*e){
    while(e->range<RC_TOP){
        if(e->pos>=e->cap)rce_grow(e);
        e->buf[e->pos++]=(u8)(e->low>>56);
        e->low<<=8;e->range<<=8;
    }
}
static void rce_encode(RCEnc*e,u32 cl,u32 ch,u32 tot){
    u64 r=e->range/tot;
    u128 sum=(u128)e->low+(u128)cl*r;
    if(sum>>64){for(u64 i=e->pos;i>0;i--){e->buf[i-1]++;if(e->buf[i-1]!=0)break;}}
    e->low=(u64)sum;
    e->range=(u64)(ch-cl)*r;
    rce_norm(e);
}
static void rce_flush(RCEnc*e){for(int i=0;i<8;i++){if(e->pos>=e->cap)rce_grow(e);e->buf[e->pos++]=(u8)(e->low>>56);e->low<<=8;}}
static void rce_byte(RCEnc*e,u8 b){
    u64 r=e->range>>8;
    u128 sum=(u128)e->low+(u128)b*r;
    if(sum>>64){for(u64 i=e->pos;i>0;i--){e->buf[i-1]++;if(e->buf[i-1]!=0)break;}}
    e->low=(u64)sum;e->range=r;rce_norm(e);
}
static void rce_varint(RCEnc*e,u64 v){while(v>=128){rce_byte(e,(u8)((v&0x7F)|0x80));v>>=7;}rce_byte(e,(u8)v);}

typedef struct { u64 low, range, code; const u8 *buf; u64 pos, len; } RCDec;
static RCDec rcd_new(const u8*buf,u64 len){RCDec d;d.buf=buf;d.len=len;d.pos=0;d.low=0;d.range=~(u64)0;d.code=0;for(int i=0;i<8&&d.pos<len;i++)d.code=(d.code<<8)|buf[d.pos++];return d;}
static void rcd_norm(RCDec*d){while(d->range<RC_TOP){d->code=(d->code<<8)|(d->pos<d->len?d->buf[d->pos++]:0);d->low<<=8;d->range<<=8;}}
static int rcd_sym(RCDec*d,const u32*cum,int nsyms){
    u64 r=d->range/cum[nsyms];u64 val=(d->code-d->low)/r;
    if(val>=cum[nsyms])val=cum[nsyms]-1;
    int lo=0,hi=nsyms;while(lo<hi){int mid=(lo+hi)/2;if(cum[mid+1]<=val)lo=mid+1;else hi=mid;}
    d->low+=cum[lo]*r;d->range=(cum[lo+1]-cum[lo])*r;rcd_norm(d);return lo;
}
static u8 rcd_byte(RCDec*d){u64 r=d->range>>8;u64 val=(d->code-d->low)/r;if(val>=256)val=255;
    d->low+=(u64)val*r;d->range=r;rcd_norm(d);return(u8)val;}
static u64 rcd_varint(RCDec*d){u64 v=0;int s=0;while(1){u8 b=rcd_byte(d);v|=(u64)(b&0x7F)<<s;s+=7;if(!(b&0x80))break;}return v;}

#define NSYMS 34
#define SYM_ESC 32
#define SYM_END 33

/* Canonical Huffman: build code lengths via package-merge-like method,
 * then assign canonical codes. Encode = table lookup. Decode = table lookup
 * over a fixed-width prefix. */
typedef struct {
    u8  len[NSYMS];      /* code length per symbol (bits) */
    u32 code[NSYMS];     /* canonical code per symbol */
    /* Decode acceleration: 12-bit lookup table */
    u8  dec_sym[4096];
    u8  dec_len[4096];
} HModel;

/* Simple Huffman code length builder using sorted array merging.
 * For 34-symbol alphabet, this is fast enough without a real heap. */
static void huff_lengths(const u32 *freq, u8 *len) {
    /* Each node: weight, left, right. Leaves have left=-1.
     * Build until only one root remains, then walk to assign lengths.
     *
     * IMPORTANT: cap the freq ratio so the resulting code length never
     * exceeds 24 bits. With 34 symbols, max depth = 24 means freq ratio
     * can be at most 2^24 ≈ 16M. We cap at 2^20 to leave headroom for
     * structural imbalance from the merge order. */
    int N = NSYMS;
    int parent[2*NSYMS];
    int weight[2*NSYMS];
    int active[2*NSYMS];
    /* Find max freq to compute the floor */
    u32 maxf = 1;
    for (int i = 0; i < N; i++) if (freq[i] > maxf) maxf = freq[i];
    u32 floor_w = maxf >> 20;  /* ratio cap = 2^20 */
    if (floor_w < 1) floor_w = 1;
    int n_active = 0;
    for (int i = 0; i < N; i++) {
        u32 f = freq[i] ? freq[i] : 1;
        if (f < floor_w) f = floor_w;
        weight[i] = (int)f;
        parent[i] = -1;
        active[n_active++] = i;
    }
    int next_node = N;
    while (n_active > 1) {
        /* Find two smallest */
        int i1 = 0, i2 = 1;
        if (weight[active[i2]] < weight[active[i1]]) { int t=i1;i1=i2;i2=t; }
        for (int k = 2; k < n_active; k++) {
            int w = weight[active[k]];
            if (w < weight[active[i1]]) { i2 = i1; i1 = k; }
            else if (w < weight[active[i2]]) { i2 = k; }
        }
        int a = active[i1], b = active[i2];
        weight[next_node] = weight[a] + weight[b];
        parent[next_node] = -1;
        parent[a] = next_node;
        parent[b] = next_node;
        /* Replace i1 with new node, remove i2 */
        active[i1] = next_node;
        if (i2 == n_active - 1) { n_active--; }
        else { active[i2] = active[--n_active]; }
        next_node++;
    }
    /* Assign lengths by walking parents to root */
    for (int i = 0; i < N; i++) {
        int depth = 0;
        int p = parent[i];
        while (p != -1) { depth++; p = parent[p]; }
        if (depth == 0) depth = 1;  /* single-symbol case */
        if (depth > 24) depth = 24;  /* clamp to keep table sane */
        len[i] = (u8)depth;
    }
}

/* Build canonical Huffman codes given lengths.
 * Standard canonical assignment: sort by (len, symbol_index), assign
 * sequential codes within each length. */
static void huff_canonical(HModel *m) {
    /* Count symbols per length */
    int bl_count[32] = {0};
    for (int i = 0; i < NSYMS; i++) bl_count[m->len[i]]++;
    /* Compute first code for each length */
    u32 next_code[32] = {0};
    u32 code = 0;
    bl_count[0] = 0;
    for (int bits = 1; bits <= 24; bits++) {
        code = (code + bl_count[bits-1]) << 1;
        next_code[bits] = code;
    }
    /* Assign codes by symbol index (canonical: sorted within length by sym idx) */
    for (int i = 0; i < NSYMS; i++) {
        int L = m->len[i];
        if (L > 0) {
            m->code[i] = next_code[L]++;
        } else {
            m->code[i] = 0;
        }
    }
    /* Build 12-bit decode lookup table.
     * For each symbol with len <= 12, fill all 12-bit prefixes that start with its code. */
    for (int i = 0; i < 4096; i++) { m->dec_sym[i] = 0; m->dec_len[i] = 0; }
    for (int i = 0; i < NSYMS; i++) {
        int L = m->len[i];
        if (L == 0 || L > 12) continue;
        u32 c = m->code[i];
        u32 prefix = c << (12 - L);
        u32 fill = 1u << (12 - L);
        for (u32 j = 0; j < fill; j++) {
            m->dec_sym[prefix + j] = (u8)i;
            m->dec_len[prefix + j] = (u8)L;
        }
    }
}

static void hm_build(HModel *m, const u32 *freq) {
    huff_lengths(freq, m->len);
    huff_canonical(m);
}

/* === Bit-level encoder appended to RCEnc-like buffer === */
typedef struct { u8 *buf; u64 cap, pos; u64 bitbuf; int nbits; } BWEnc;
static BWEnc bw_new(u64 cap) { BWEnc e; e.buf=calloc(cap,1); e.cap=cap; e.pos=0; e.bitbuf=0; e.nbits=0; return e; }
static void bw_grow(BWEnc *e) { e->cap*=2; e->buf=realloc(e->buf, e->cap); }
static inline void bw_write(BWEnc *e, u32 code, int len) {
    e->bitbuf = (e->bitbuf << len) | (u64)code;
    e->nbits += len;
    while (e->nbits >= 8) {
        if (e->pos >= e->cap) bw_grow(e);
        e->nbits -= 8;
        e->buf[e->pos++] = (u8)(e->bitbuf >> e->nbits);
    }
}
static void bw_flush(BWEnc *e) {
    if (e->nbits > 0) {
        if (e->pos >= e->cap) bw_grow(e);
        e->buf[e->pos++] = (u8)(e->bitbuf << (8 - e->nbits));
        e->nbits = 0;
        e->bitbuf = 0;
    }
}
/* Append varint bytes (for escape values) — byte-aligned, simpler */
static void bw_varint(BWEnc *e, u64 v) {
    bw_flush(e);
    while (v >= 128) {
        if (e->pos >= e->cap) bw_grow(e);
        e->buf[e->pos++] = (u8)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    if (e->pos >= e->cap) bw_grow(e);
    e->buf[e->pos++] = (u8)v;
}

typedef struct { const u8 *buf; u64 len, pos; u64 bitbuf; int nbits; } BWDec;
static BWDec bwd_new(const u8 *buf, u64 len) { BWDec d; d.buf=buf; d.len=len; d.pos=0; d.bitbuf=0; d.nbits=0; return d; }
static inline void bwd_fill(BWDec *d) {
    while (d->nbits <= 56 && d->pos < d->len) {
        d->bitbuf = (d->bitbuf << 8) | d->buf[d->pos++];
        d->nbits += 8;
    }
}
static inline u32 bwd_peek(BWDec *d, int n) {
    bwd_fill(d);
    if (d->nbits < n) return 0;
    return (u32)((d->bitbuf >> (d->nbits - n)) & ((1u << n) - 1));
}
static inline void bwd_consume(BWDec *d, int n) { d->nbits -= n; }
static u64 bwd_varint(BWDec *d) {
    /* Sync to byte boundary to match encoder's bw_flush. The encoder padded
     * with zeros to the next byte boundary. The decoder must skip those
     * pad bits. Round nbits down to the nearest multiple of 8. */
    d->nbits &= ~7;
    u64 v = 0;
    int s = 0;
    while (1) {
        if (d->pos >= d->len && d->nbits == 0) break;
        u8 b;
        if (d->nbits >= 8) { b = (u8)((d->bitbuf >> (d->nbits - 8)) & 0xFF); d->nbits -= 8; }
        else { b = d->buf[d->pos++]; }
        v |= (u64)(b & 0x7F) << s;
        s += 7;
        if (!(b & 0x80)) break;
    }
    return v;
}

/* Slow fallback for long Huffman codes (>12 bits). Rarely fires for our
 * 34-symbol alphabet because the typical model has all codes <= 8 bits.
 * Marked __attribute__((noinline)) to keep the fast path tiny. */
static __attribute__((noinline)) int decode_long(BWDec *d, const HModel *m) {
    u32 code = 0;
    for (int L = 1; L <= 24; L++) {
        bwd_fill(d);
        if (d->nbits == 0) return 0;
        code = (code << 1) | ((d->bitbuf >> (d->nbits - 1)) & 1);
        d->nbits--;
        for (int i = 0; i < NSYMS; i++) {
            if (m->len[i] == L && m->code[i] == code) return i;
        }
    }
    return 0;
}

static __attribute__((always_inline)) inline void encode_val(BWEnc *e, const HModel *m, u64 v) {
    int sym;
    if (__builtin_expect(v == 0, 0)) sym = SYM_END;
    else if (__builtin_expect(v <= 32, 1)) sym = (int)(v - 1);
    else sym = SYM_ESC;
    bw_write(e, m->code[sym], m->len[sym]);
    if (__builtin_expect(sym == SYM_ESC, 0)) bw_varint(e, v);
}

static __attribute__((always_inline)) inline u64 decode_val(BWDec *d, const HModel *m) {
    bwd_fill(d);
    /* Peek 12 bits */
    u32 peek;
    if (__builtin_expect(d->nbits >= 12, 1)) {
        peek = (u32)((d->bitbuf >> (d->nbits - 12)) & 0xFFF);
    } else {
        peek = (u32)((d->bitbuf << (12 - d->nbits)) & 0xFFF);
    }
    int sym = m->dec_sym[peek];
    int len = m->dec_len[peek];
    if (__builtin_expect(len == 0, 0)) {
        sym = decode_long(d, m);
    } else {
        d->nbits -= len;
    }
    if (__builtin_expect(sym == SYM_END, 0)) return 0;
    if (__builtin_expect(sym < 32, 1)) return (u64)(sym + 1);
    /* Escape: read literal varint */
    return bwd_varint(d);
}

typedef HModel FModel;  /* Keep name compatible */
#define fm_build hm_build

/* Sparse index for O(sqrt(n)) ac_contains.
 * Built lazily on first ac_contains call. Checkpoints every IDX_STRIDE
 * intervals record the decoder state (byte position + bit buffer) and the
 * last_end value at that point, so ac_contains can skip ahead without
 * decoding from the start. */
#define IDX_STRIDE 1024
typedef struct {
    i64 last_end;      /* last_end value AFTER decoding this checkpoint's intervals */
    u64 byte_pos;      /* byte position in rc_buf */
    u64 bitbuf;        /* bit buffer state */
    int nbits;         /* bits in buffer */
    u64 iv_count;      /* number of intervals decoded before this checkpoint */
} IdxEntry;

typedef struct{
    u8*rc_buf;u64 rc_len,rc_cap;
    u64 count,popcount;i64 search_T;
    HModel gm,rm;HModel enc_gm,enc_rm;
    IdxEntry *idx;     /* sparse index, NULL until first ac_contains */
    u64 idx_n;
}ACFront;
typedef struct{i64*starts;u64*runs;u64 count;}IvArrays;


static void ac_encode(ACFront*f,const i64*starts,const u64*runs,u64 n){
    BWEnc enc=bw_new(n*4+1024);
    /* First start as varint, byte-aligned */
    bw_varint(&enc,(u64)(starts[0]+1));
    encode_val(&enc,&f->rm,runs[0]);
    for(u64 i=1;i<n;i++){
        u64 gap=(u64)(starts[i]-(starts[i-1]+(i64)runs[i-1]));
        encode_val(&enc,&f->gm,gap);
        encode_val(&enc,&f->rm,runs[i]);
    }
    /* Terminator: encode gap=0 (which maps to SYM_END) */
    encode_val(&enc,&f->gm,0);
    bw_flush(&enc);
    free(f->rc_buf);f->rc_buf=enc.buf;f->rc_len=enc.pos;f->rc_cap=enc.cap;f->count=n;
}

static IvArrays ac_decode(const ACFront*f){
    IvArrays ia;ia.count=0;u64 cap=f->count+16;
    ia.starts=malloc(cap*8);ia.runs=malloc(cap*8);
    BWDec dec=bwd_new(f->rc_buf,f->rc_len);
    i64 start=(i64)bwd_varint(&dec)-1;
    u64 run=decode_val(&dec,&f->rm);
    if(run==0){return ia;}
    ia.starts[0]=start;ia.runs[0]=run;ia.count=1;
    while(1){
        u64 gap=decode_val(&dec,&f->gm);
        if(gap==0)break;
        start+=(i64)run+(i64)gap;
        run=decode_val(&dec,&f->rm);
        if(ia.count>=cap){cap*=2;ia.starts=realloc(ia.starts,cap*8);ia.runs=realloc(ia.runs,cap*8);}
        ia.starts[ia.count]=start;ia.runs[ia.count]=run;ia.count++;
    }
    return ia;
}

/* Streaming source iterator: decodes one interval at a time from the
 * encoded front buffer, no materialization. */
typedef struct {
    BWDec dec;
    const HModel *gm, *rm;
    int started;
    int eof;
    i64 cur_start;
    u64 cur_run;
    i64 shift;  /* added to cur_start when reported */
} SrcIter;

static void si_init(SrcIter *si, const u8 *buf, u64 len,
                    const HModel *gm, const HModel *rm, i64 shift) {
    si->dec = bwd_new(buf, len);
    si->gm = gm; si->rm = rm;
    si->started = 0; si->eof = 0;
    si->cur_start = 0; si->cur_run = 0;
    si->shift = shift;
}
/* Pull next interval. Returns 1 if got one, 0 if end of stream. */
static inline int si_next(SrcIter *si) {
    if (si->eof) return 0;
    if (!si->started) {
        si->cur_start = (i64)bwd_varint(&si->dec) - 1 + si->shift;
        si->cur_run = decode_val(&si->dec, si->rm);
        si->started = 1;
        if (si->cur_run == 0) { si->eof = 1; return 0; }
        return 1;
    }
    u64 gap = decode_val(&si->dec, si->gm);
    if (gap == 0) { si->eof = 1; return 0; }
    si->cur_start += (i64)si->cur_run + (i64)gap;
    si->cur_run = decode_val(&si->dec, si->rm);
    if (si->cur_run == 0) { si->eof = 1; return 0; }
    return 1;
}

/* Helper: stream the merge once, calling cb(ctx, cs, cl) for each output
 * interval. Used twice in ac_shl_or — once to gather frequencies, once
 * to encode. */
typedef void (*MergeCB)(void *ctx, i64 cs, u64 cl);

static void merge_stream(const u8 *buf, u64 len, const HModel *gm, const HModel *rm,
                         i64 shift, i64 search_T, MergeCB cb, void *ctx) {
    SrcIter A, B;
    si_init(&A, buf, len, gm, rm, 0);
    si_init(&B, buf, len, gm, rm, shift);

    int av = si_next(&A); int bv = si_next(&B);
    i64 a_s = av ? A.cur_start : 0; u64 a_l = av ? A.cur_run : 0;
    i64 b_s = bv ? B.cur_start : 0; u64 b_l = bv ? B.cur_run : 0;

    while (bv && b_s + (i64)b_l <= 0) {
        bv = si_next(&B);
        if (bv) { b_s = B.cur_start; b_l = B.cur_run; }
    }
    if (bv && b_s < 0) { b_l += b_s; b_s = 0; }
    while (bv && b_s > search_T) {
        bv = si_next(&B);
        if (bv) { b_s = B.cur_start; b_l = B.cur_run; }
    }

    while (av || bv) {
        i64 cs; u64 cl;
        if (av && (!bv || a_s <= b_s)) {
            cs = a_s; cl = a_l;
            av = si_next(&A);
            if (av) { a_s = A.cur_start; a_l = A.cur_run; }
        } else {
            cs = b_s; cl = b_l;
            if (cs > search_T) { bv = 0; continue; }
            if (cs + (i64)cl > search_T + 1) cl = (u64)(search_T + 1 - cs);
            bv = si_next(&B);
            if (bv) { b_s = B.cur_start; b_l = B.cur_run; }
            while (bv && b_s > search_T) {
                bv = si_next(&B);
                if (bv) { b_s = B.cur_start; b_l = B.cur_run; }
            }
        }
        i64 ce = cs + (i64)cl;
        if (ce > search_T + 1) ce = search_T + 1;

        while (av || bv) {
            if (av && a_s <= ce) {
                i64 ae = a_s + (i64)a_l;
                if (ae > ce) ce = ae;
                if (ae > search_T + 1) ce = search_T + 1;
                av = si_next(&A);
                if (av) { a_s = A.cur_start; a_l = A.cur_run; }
            } else if (bv && b_s <= ce) {
                i64 be = b_s + (i64)b_l;
                if (be > search_T + 1) be = search_T + 1;
                if (be > ce) ce = be;
                bv = si_next(&B);
                if (bv) { b_s = B.cur_start; b_l = B.cur_run; }
            } else break;
        }
        if (ce <= cs) continue;
        cb(ctx, cs, (u64)(ce - cs));
    }
}

/* Pass-1 callback: count output symbol frequencies. */
typedef struct {
    int first;
    i64 last_end;
    u64 count;
    u64 popcount;
    u32 gf[NSYMS];
    u32 rf[NSYMS];
} FreqCtx;
static void freq_cb(void *vctx, i64 cs, u64 cl) {
    FreqCtx *c = (FreqCtx*)vctx;
    if (c->first) {
        c->rf[cl <= 32 ? (int)(cl - 1) : SYM_ESC]++;
        c->first = 0;
    } else {
        u64 gap = (u64)(cs - c->last_end);
        c->gf[gap <= 32 ? (int)(gap - 1) : SYM_ESC]++;
        c->rf[cl <= 32 ? (int)(cl - 1) : SYM_ESC]++;
    }
    c->last_end = cs + (i64)cl;
    c->count++;
    c->popcount += cl;
}

/* Pass-2 callback: encode output using freshly built model. */
typedef struct {
    BWEnc enc;
    const HModel *gm, *rm;
    int first;
    i64 last_end;
} EncCtx;
static void enc_cb(void *vctx, i64 cs, u64 cl) {
    EncCtx *c = (EncCtx*)vctx;
    if (c->first) {
        bw_varint(&c->enc, (u64)(cs + 1));
        encode_val(&c->enc, c->rm, cl);
        c->first = 0;
    } else {
        u64 gap = (u64)(cs - c->last_end);
        encode_val(&c->enc, c->gm, gap);
        encode_val(&c->enc, c->rm, cl);
    }
    c->last_end = cs + (i64)cl;
}

/* Accumulators for diagnosing time split (in nanoseconds) */
static u64 t_pass1_ns = 0, t_pass2_ns = 0, t_model_ns = 0, t_alloc_ns = 0;
static inline u64 nanos(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (u64)ts.tv_sec*1000000000ULL+ts.tv_nsec;}

/* Combined encoder + stats callback. Encodes with the lagging model
 * (passed via ec.gm/rm pointing to f->enc_gm/rm) and accumulates output
 * frequencies into ec.gf/rf for the next merge's encode model. */
typedef struct {
    BWEnc enc;
    const HModel *gm, *rm;     /* lagging encode model */
    int first;
    i64 last_end;
    u64 count;
    u64 popcount;
    u32 gf[NSYMS];
    u32 rf[NSYMS];
} CombCtx;

static void comb_cb(void *vctx, i64 cs, u64 cl) {
    CombCtx *c = (CombCtx*)vctx;
    if (c->first) {
        bw_varint(&c->enc, (u64)(cs + 1));
        encode_val(&c->enc, c->rm, cl);
        c->rf[cl <= 32 ? (int)(cl - 1) : SYM_ESC]++;
        c->first = 0;
    } else {
        u64 gap = (u64)(cs - c->last_end);
        encode_val(&c->enc, c->gm, gap);
        encode_val(&c->enc, c->rm, cl);
        c->gf[gap <= 32 ? (int)(gap - 1) : SYM_ESC]++;
        c->rf[cl <= 32 ? (int)(cl - 1) : SYM_ESC]++;
    }
    c->last_end = cs + (i64)cl;
    c->count++;
    c->popcount += cl;
}

static void ac_shl_or(ACFront *f, i64 shift) {
    u64 t0 = nanos();
    /* Single pass: merge + encode (with lagging model) + collect stats */
    CombCtx cc;
    u64 cap_hint = f->rc_len * 2 + 1024;
    if (cap_hint < 4096) cap_hint = 4096;
    cc.enc = bw_new(cap_hint);
    cc.gm = &f->enc_gm; cc.rm = &f->enc_rm;
    cc.first = 1; cc.last_end = 0; cc.count = 0; cc.popcount = 0;
    for (int i = 0; i < NSYMS; i++) { cc.gf[i] = 0; cc.rf[i] = 0; }

    merge_stream(f->rc_buf, f->rc_len, &f->gm, &f->rm, shift, f->search_T,
                 comb_cb, &cc);

    encode_val(&cc.enc, &f->enc_gm, 0);  /* terminator */
    cc.gf[SYM_END]++;
    bw_flush(&cc.enc);
    u64 t1 = nanos();

    /* Build the next-step encode model from observed output frequencies */
    HModel next_gm, next_rm;
    fm_build(&next_gm, cc.gf);
    fm_build(&next_rm, cc.rf);
    u64 t2 = nanos();

    /* Replace front buffer.  The new buffer was encoded with f->enc_gm/rm,
     * so promote those to f->gm/rm.  The freshly built next model becomes
     * the lagging encode model for the next call. */
    free(f->rc_buf);
    f->rc_buf = cc.enc.buf;
    f->rc_len = cc.enc.pos;
    f->rc_cap = cc.enc.cap;
    /* Buffer was replaced; old index (if any) is stale */
    if (f->idx) { free(f->idx); f->idx = NULL; f->idx_n = 0; }
    f->count = cc.count;
    f->popcount = cc.popcount;
    f->gm = f->enc_gm;
    f->rm = f->enc_rm;
    f->enc_gm = next_gm;
    f->enc_rm = next_rm;

    t_pass1_ns += (t1 - t0);
    t_model_ns += (t2 - t1);
    t_pass2_ns += 0;
    t_alloc_ns += 0;
}

/* Build sparse index by walking the frontier once. Stores a checkpoint every
 * IDX_STRIDE intervals. Each checkpoint captures the BWDec state (byte_pos,
 * bitbuf, nbits) and the last_end value so a later query can resume decoding
 * from there instead of re-decoding from the beginning. */
static void ac_build_index(ACFront *f) {
    if (f->idx || f->count == 0) return;
    u64 n_cp = (f->count / IDX_STRIDE) + 1;
    f->idx = malloc(n_cp * sizeof(IdxEntry));
    f->idx_n = 0;
    BWDec dec = bwd_new(f->rc_buf, f->rc_len);
    i64 start = (i64)bwd_varint(&dec) - 1;
    u64 run = decode_val(&dec, &f->rm);
    if (run == 0) return;
    i64 last_end = start + (i64)run;
    u64 iv = 1;
    while (1) {
        if (iv % IDX_STRIDE == 0 && f->idx_n < n_cp) {
            IdxEntry *e = &f->idx[f->idx_n++];
            e->last_end = last_end;
            e->byte_pos = dec.pos;
            e->bitbuf = dec.bitbuf;
            e->nbits = dec.nbits;
            e->iv_count = iv;
        }
        u64 gap = decode_val(&dec, &f->gm);
        if (gap == 0) break;
        start = last_end + (i64)gap;
        run = decode_val(&dec, &f->rm);
        if (run == 0) break;
        last_end = start + (i64)run;
        iv++;
    }
}

/* Check if target is in the encoded front. Uses the sparse index when
 * available to skip ahead; otherwise linear scan.
 *
 * NOTE: takes ACFront* (not const) because it lazily builds the index on
 * first call. Subsequent calls hit the index. */
static int ac_contains(ACFront *f, i64 target) {
    if (f->count == 0) return 0;

    /* Build index lazily on first call for large frontiers.
     * For small frontiers, linear scan is fine — skip the index overhead. */
    if (!f->idx && f->count >= IDX_STRIDE * 4) {
        ac_build_index(f);
    }

    BWDec dec;
    i64 start, last_end;
    u64 run;

    if (f->idx && f->idx_n > 0) {
        /* Binary-search for the largest checkpoint whose last_end < target.
         * If found, resume decoding from there. Otherwise, start from scratch. */
        u64 lo = 0, hi = f->idx_n;
        while (lo < hi) {
            u64 mid = (lo + hi) / 2;
            if (f->idx[mid].last_end < target) lo = mid + 1;
            else hi = mid;
        }
        if (lo > 0) {
            /* Resume from checkpoint lo-1 */
            IdxEntry *e = &f->idx[lo - 1];
            dec.buf = f->rc_buf;
            dec.len = f->rc_len;
            dec.pos = e->byte_pos;
            dec.bitbuf = e->bitbuf;
            dec.nbits = e->nbits;
            last_end = e->last_end;
            /* Next symbol is a gap (we stopped between intervals) */
            u64 gap = decode_val(&dec, &f->gm);
            if (gap == 0) return 0;
            start = last_end + (i64)gap;
            run = decode_val(&dec, &f->rm);
            if (run == 0) return 0;
            last_end = start + (i64)run;
            if (target < start) return 0;
            if (target < last_end) return 1;
            goto linear_scan;
        }
    }

    /* Fallback: start from the beginning */
    dec = bwd_new(f->rc_buf, f->rc_len);
    start = (i64)bwd_varint(&dec) - 1;
    run = decode_val(&dec, &f->rm);
    if (run == 0) return 0;
    last_end = start + (i64)run;
    if (target >= start && target < last_end) return 1;
    if (target < start) return 0;

linear_scan:
    while (1) {
        u64 gap = decode_val(&dec, &f->gm);
        if (gap == 0) return 0;
        start = last_end + (i64)gap;
        run = decode_val(&dec, &f->rm);
        if (run == 0) return 0;
        last_end = start + (i64)run;
        if (target < start) return 0;
        if (target < last_end) return 1;
    }
}

/* Initialize a Huffman front seeded with a single position p (=0 typically).
 * Uses a uniform frequency seed model so the first merge's decode works. */
/* === Frontier disk persistence for reconstruction === */
#define CRISP_MAGIC "CRISP1\0\0"

/* Frontier file format (v3):
 *   magic "CRISP3\0\0"
 *   step_idx, count, popcount, search_T, rc_len  (five u64)
 *   four HModels (gm, rm, enc_gm, enc_rm)
 *   rc_buf[rc_len]
 */
#undef CRISP_MAGIC
#define CRISP_MAGIC "CRISP3\0\0"

static int frontier_save(const ACFront *f, const char *path, u64 step_idx) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    fwrite(CRISP_MAGIC, 1, 8, fp);
    fwrite(&step_idx, sizeof(u64), 1, fp);
    fwrite(&f->count, sizeof(u64), 1, fp);
    fwrite(&f->popcount, sizeof(u64), 1, fp);
    fwrite(&f->search_T, sizeof(i64), 1, fp);
    fwrite(&f->rc_len, sizeof(u64), 1, fp);
    fwrite(&f->gm, sizeof(HModel), 1, fp);
    fwrite(&f->rm, sizeof(HModel), 1, fp);
    fwrite(&f->enc_gm, sizeof(HModel), 1, fp);
    fwrite(&f->enc_rm, sizeof(HModel), 1, fp);
    if (f->rc_len > 0) fwrite(f->rc_buf, 1, f->rc_len, fp);
    fclose(fp);
    return 1;
}

static int frontier_load(ACFront *f, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    char magic[8];
    if (fread(magic, 1, 8, fp) != 8 || memcmp(magic, CRISP_MAGIC, 8)) {
        fclose(fp); return 0;
    }
    u64 step_idx;
    fread(&step_idx, sizeof(u64), 1, fp);
    fread(&f->count, sizeof(u64), 1, fp);
    fread(&f->popcount, sizeof(u64), 1, fp);
    fread(&f->search_T, sizeof(i64), 1, fp);
    fread(&f->rc_len, sizeof(u64), 1, fp);
    fread(&f->gm, sizeof(HModel), 1, fp);
    fread(&f->rm, sizeof(HModel), 1, fp);
    fread(&f->enc_gm, sizeof(HModel), 1, fp);
    fread(&f->enc_rm, sizeof(HModel), 1, fp);
    f->rc_cap = f->rc_len;
    f->rc_buf = (f->rc_len > 0) ? malloc(f->rc_len) : NULL;
    if (f->rc_len > 0) fread(f->rc_buf, 1, f->rc_len, fp);
    f->idx = NULL; f->idx_n = 0;
    fclose(fp);
    return 1;
}

/* === Run metadata (plain text) === */
static int meta_save(const char *path, int n, i64 R, int seed,
                     int planted_k, i64 planted_T, i64 total, i64 search_T,
                     const i64 *items) {
    FILE *fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp, "version 1\n");
    fprintf(fp, "n %d\n", n);
    fprintf(fp, "R %lld\n", (long long)R);
    fprintf(fp, "seed %d\n", seed);
    fprintf(fp, "planted_k %d\n", planted_k);
    fprintf(fp, "planted_T %lld\n", (long long)planted_T);
    fprintf(fp, "total %lld\n", (long long)total);
    fprintf(fp, "search_T %lld\n", (long long)search_T);
    fprintf(fp, "items");
    for (int i = 0; i < n; i++) fprintf(fp, " %lld", (long long)items[i]);
    fprintf(fp, "\n");
    fclose(fp);
    return 1;
}

static int meta_load(const char *path, int *n_out, i64 *R_out, int *seed_out,
                     int *planted_k_out, i64 *planted_T_out, i64 *total_out,
                     i64 *search_T_out, i64 **items_out) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char *line = malloc(1 << 20);
    int n = 0;
    i64 *items = NULL;
    *planted_k_out = -1; *planted_T_out = 0; *total_out = 0; *search_T_out = 0;
    while (fgets(line, 1 << 20, fp)) {
        if (!strncmp(line, "n ", 2)) { n = atoi(line + 2); *n_out = n; }
        else if (!strncmp(line, "R ", 2)) *R_out = atoll(line + 2);
        else if (!strncmp(line, "seed ", 5)) *seed_out = atoi(line + 5);
        else if (!strncmp(line, "planted_k ", 10)) *planted_k_out = atoi(line + 10);
        else if (!strncmp(line, "planted_T ", 10)) *planted_T_out = atoll(line + 10);
        else if (!strncmp(line, "total ", 6)) *total_out = atoll(line + 6);
        else if (!strncmp(line, "search_T ", 9)) *search_T_out = atoll(line + 9);
        else if (!strncmp(line, "items", 5)) {
            if (n <= 0) { free(line); fclose(fp); return 0; }
            items = malloc(n * sizeof(i64));
            char *p = line + 5;
            for (int i = 0; i < n; i++) {
                while (*p == ' ' || *p == '\t') p++;
                items[i] = strtoll(p, &p, 10);
            }
        }
    }
    free(line);
    fclose(fp);
    if (!items) return 0;
    *items_out = items;
    return 1;
}

/* Highest step N such that <dir>/frontier_NNNN.bin exists. Returns -1 if none. */
static int find_max_frontier_step(const char *dir) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "ls %s/frontier_*.bin 2>/dev/null | sort | tail -1", dir);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    char buf[1024];
    int step = -1;
    if (fgets(buf, sizeof(buf), fp)) {
        char *p = strstr(buf, "frontier_");
        if (p) step = atoi(p + 9);
    }
    pclose(fp);
    return step;
}

static void frontier_free(ACFront *f) {
    if (f->rc_buf) { free(f->rc_buf); f->rc_buf = NULL; }
    if (f->idx) { free(f->idx); f->idx = NULL; f->idx_n = 0; }
    f->rc_len = 0; f->rc_cap = 0;
}

/* === Solution file writer === */
/* Simple linear-probing hash set over strings, used to dedupe solutions. */
typedef struct {
    char **slots;
    u64 cap;
    u64 n;
} StrSet;
static void ss_init(StrSet *s, u64 cap){
    s->cap = cap;
    s->n = 0;
    s->slots = calloc(cap, sizeof(char*));
}
static u64 ss_hash(const char *s){
    u64 h = 1469598103934665603ULL;
    while (*s) { h ^= (u64)(u8)*s++; h *= 1099511628211ULL; }
    return h;
}
static void ss_grow(StrSet *s);
static int ss_add(StrSet *s, const char *key){
    if (s->n * 2 >= s->cap) ss_grow(s);
    u64 h = ss_hash(key);
    u64 i = h & (s->cap - 1);
    while (s->slots[i]){
        if (!strcmp(s->slots[i], key)) return 0; /* already present */
        i = (i + 1) & (s->cap - 1);
    }
    s->slots[i] = strdup(key);
    s->n++;
    return 1;
}
static void ss_grow(StrSet *s){
    u64 oldcap = s->cap;
    char **old = s->slots;
    s->cap *= 2;
    s->slots = calloc(s->cap, sizeof(char*));
    s->n = 0;
    for (u64 i = 0; i < oldcap; i++) if (old[i]) { ss_add(s, old[i]); free(old[i]); }
    free(old);
}
static void ss_free(StrSet *s){
    for (u64 i = 0; i < s->cap; i++) if (s->slots[i]) free(s->slots[i]);
    free(s->slots);
    s->slots = NULL; s->cap = 0; s->n = 0;
}

typedef struct {
    FILE *fp;
    u64 count;
    u64 limit;
    u64 per_k_limit;      /* cap for find-k mode; defaults to `limit` if unset */
    int min_k_seen;
    int max_k_seen;
    StrSet seen;
    /* --find-k support: when find_k_n > 0, switch behavior.
     *   - For k in find_k[]: store every solution found at that k
     *     (no per-k cap), and find_k_found[] tracks the count.
     *   - For k NOT in find_k[]: store only ONE solution as a representative
     *     (tracked via seen_k_one[]).
     *   - The walker should not stop on --limit; it walks to completion.
     */
    int *find_k;          /* requested ks (NULL if not used) */
    int find_k_n;
    u64 *find_k_found;    /* per-k solution count, parallel to find_k */
    u8 *seen_k_one;       /* seen_k_one[k] != 0 means one rep was already emitted */
    int seen_k_one_cap;
    u64 dedup_streak;     /* consecutive dedup rejections without a new unique solution */
    int exhausted;        /* set to 1 when dedup_streak exceeds threshold */
} SolWriter;

static void solw_init(SolWriter *sw, const char *path, u64 limit) {
    sw->fp = fopen(path, "w");
    sw->count = 0;
    sw->limit = limit;
    sw->per_k_limit = limit;  /* default; overridden by --per-k-limit */
    sw->min_k_seen = INT32_MAX;
    sw->max_k_seen = 0;
    ss_init(&sw->seen, 1024);
    sw->find_k = NULL;
    sw->find_k_n = 0;
    sw->find_k_found = NULL;
    sw->seen_k_one = NULL;
    sw->seen_k_one_cap = 0;
    sw->dedup_streak = 0;
    sw->exhausted = 0;
}
/* Configure --find-k mode. Pass an array of requested ks and the max
 * possible k (= n). Allocates internal tracking. */
static void solw_set_find_k(SolWriter *sw, const int *ks, int n_ks, int max_k) {
    sw->find_k = malloc(n_ks * sizeof(int));
    sw->find_k_n = n_ks;
    sw->find_k_found = calloc(n_ks, sizeof(u64));
    for (int i = 0; i < n_ks; i++) sw->find_k[i] = ks[i];
    sw->seen_k_one_cap = max_k + 2;
    sw->seen_k_one = calloc(sw->seen_k_one_cap, sizeof(u8));
}
static void solw_close(SolWriter *sw) {
    if (sw->fp) { fclose(sw->fp); sw->fp = NULL; }
    ss_free(&sw->seen);
    if (sw->find_k) { free(sw->find_k); sw->find_k = NULL; }
    if (sw->find_k_found) { free(sw->find_k_found); sw->find_k_found = NULL; }
    if (sw->seen_k_one) { free(sw->seen_k_one); sw->seen_k_one = NULL; }
}
/* Returns the index in sw->find_k of k, or -1 if not requested. */
static int solw_find_k_idx(const SolWriter *sw, int k) {
    for (int i = 0; i < sw->find_k_n; i++)
        if (sw->find_k[i] == k) return i;
    return -1;
}
/* Returns 1 if all requested ks have at least one found solution. */
static int solw_all_find_k_done(const SolWriter *sw) {
    for (int i = 0; i < sw->find_k_n; i++)
        if (sw->find_k_found[i] == 0) return 0;
    return 1;
}
/* Write a solution as comma-separated values plus its k for sorting later.
 * Format: "k:v1,v2,v3,...\n"  (k prefix makes the post-sort easy)
 * Duplicates (same exact value sequence) are skipped.
 *
 * In find-k mode:
 *   - For requested ks: emit every solution.
 *   - For other ks: emit only the first one seen at that k (a representative).
 */
static void solw_emit(SolWriter *sw, const i64 *values, int k) {
    if (!sw->fp) return;

    /* find-k filter */
    int fk_idx = -1;
    if (sw->find_k_n > 0) {
        fk_idx = solw_find_k_idx(sw, k);
        if (fk_idx < 0) {
            /* Not a requested k. Emit only the first observed at this k. */
            if (k >= 0 && k < sw->seen_k_one_cap && sw->seen_k_one[k]) return;
        }
    }

    /* Build the line into a temporary buffer for dedupe check */
    /* Format: k:sum:v1,v2,v3,...  */
    i64 sum = 0;
    for (int i = 0; i < k; i++) sum += values[i];
    char line[65536];
    int pos = snprintf(line, sizeof(line), "%d:%lld:", k, (long long)sum);
    for (int i = 0; i < k; i++) {
        pos += snprintf(line + pos, sizeof(line) - pos, "%lld", (long long)values[i]);
        if (i + 1 < k) line[pos++] = ',';
    }
    line[pos] = 0;
    if (!ss_add(&sw->seen, line)) {
        /* Duplicate solution — increment streak counter */
        sw->dedup_streak++;
        if (sw->dedup_streak >= 10000) {
            if (!sw->exhausted) {
                printf("  ⚠ %llu consecutive duplicate solutions — search space exhausted for unique solutions\n",
                    (unsigned long long)sw->dedup_streak);
                fflush(stdout);
            }
            sw->exhausted = 1;
        }
        return;
    }
    sw->dedup_streak = 0;  /* reset on successful emit */
    fputs(line, sw->fp); fputc('\n', sw->fp);
    sw->count++;
    if (k < sw->min_k_seen) sw->min_k_seen = k;
    if (k > sw->max_k_seen) sw->max_k_seen = k;

    /* Update per-k tracking */
    if (sw->find_k_n > 0) {
        if (fk_idx >= 0) {
            sw->find_k_found[fk_idx]++;
        } else if (k >= 0 && k < sw->seen_k_one_cap) {
            sw->seen_k_one[k] = 1;
        }
    }
}

/* Like solw_emit but does NOT increment sw->count or check the limit.
 * Used for complement emission, where the complement is a "free" extra
 * line paired with a primary solution and shouldn't consume a solution
 * slot from the user's --limit. Still respects dedupe and find-k filtering. */
static void solw_emit_extra(SolWriter *sw, const i64 *values, int k) {
    if (!sw->fp) return;

    int fk_idx = -1;
    if (sw->find_k_n > 0) {
        fk_idx = solw_find_k_idx(sw, k);
        if (fk_idx < 0) {
            if (k >= 0 && k < sw->seen_k_one_cap && sw->seen_k_one[k]) return;
        }
    }

    char line[65536];
    int pos = snprintf(line, sizeof(line), "%d:", k);
    for (int i = 0; i < k; i++) {
        pos += snprintf(line + pos, sizeof(line) - pos, "%lld", (long long)values[i]);
        if (i + 1 < k) line[pos++] = ',';
    }
    line[pos] = 0;
    if (!ss_add(&sw->seen, line)) return;
    fputs(line, sw->fp); fputc('\n', sw->fp);
    if (k < sw->min_k_seen) sw->min_k_seen = k;
    if (k > sw->max_k_seen) sw->max_k_seen = k;

    if (sw->find_k_n > 0) {
        if (fk_idx >= 0) {
            sw->find_k_found[fk_idx]++;
        } else if (k >= 0 && k < sw->seen_k_one_cap) {
            sw->seen_k_one[k] = 1;
        }
    }
}

/* Emit a solution AND its complement (the items NOT in the subset).
 * Both subsets are valid solutions to the original problem — one sums to
 * search_T, the other to (total - search_T). The complement is computed
 * by subtracting the taken values from the sorted items array.
 *
 * Both lines are written separately so the existing sort/dedup logic
 * applies to both. The complement is emitted in DESCENDING sorted order
 * to match the convention used for the primary subset (the walker emits
 * largest items first because items are sorted ascending and the walk
 * tries TAKE before SKIP starting from the highest index). */
static void solw_emit_with_complement(SolWriter *sw, const i64 *taken, int taken_k,
                                      const i64 *items_sorted, int n, int flip) {
    if (!flip) {
        /* Normal case: search_T == T, emit the taken subset directly */
        solw_emit(sw, taken, taken_k);
        return;
    }

    /* Flipped case: T > total/2, walker found subset summing to search_T.
     * The complement of that subset sums to T (the user's original target).
     * Build the complement and emit it instead. */
    i64 taken_sorted[2048];
    int tk = taken_k > 2048 ? 2048 : taken_k;
    for (int i = 0; i < tk; i++) taken_sorted[i] = taken[i];
    for (int i = 1; i < tk; i++) {
        i64 v = taken_sorted[i]; int j = i;
        while (j > 0 && taken_sorted[j-1] > v) { taken_sorted[j] = taken_sorted[j-1]; j--; }
        taken_sorted[j] = v;
    }

    /* Two-pointer walk: collect items NOT in the taken set (= complement) */
    i64 *comp = malloc((n - tk + 1) * sizeof(i64));
    int cn = 0;
    int ti = 0;
    for (int i = 0; i < n; i++) {
        if (ti < tk && items_sorted[i] == taken_sorted[ti]) {
            ti++;
        } else {
            comp[cn++] = items_sorted[i];
        }
    }
    /* Reverse to descending order (matching walker's largest-first convention) */
    for (int i = 0; i < cn / 2; i++) {
        i64 tmp = comp[i]; comp[i] = comp[cn - 1 - i]; comp[cn - 1 - i] = tmp;
    }
    solw_emit(sw, comp, cn);
    free(comp);
}

/* Post-sort the solution file so smallest-k solutions come first.
 * Reads all lines into memory, sorts, writes back.
 */
static int solline_cmp(const void *a, const void *b) {
    const char *la = *(const char**)a;
    const char *lb = *(const char**)b;
    int ka = atoi(la), kb = atoi(lb);
    if (ka != kb) return ka - kb;
    return strcmp(la, lb);
}
static void solw_sort_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char **lines = NULL;
    u64 cap = 1024, n = 0;
    lines = malloc(cap * sizeof(char*));
    char buf[65536];
    while (fgets(buf, sizeof(buf), fp)) {
        if (n >= cap) { cap *= 2; lines = realloc(lines, cap * sizeof(char*)); }
        lines[n++] = strdup(buf);
    }
    fclose(fp);
    qsort(lines, n, sizeof(char*), solline_cmp);
    /* Deduplicate: with duplicate-valued items, the walker can emit the same
     * value sequence from different item-index paths. Drop consecutive dupes. */
    u64 unique_n = 0;
    for (u64 i = 0; i < n; i++) {
        if (unique_n == 0 || strcmp(lines[unique_n - 1], lines[i]) != 0) {
            lines[unique_n++] = lines[i];
        } else {
            free(lines[i]);
        }
    }
    fp = fopen(path, "w");
    if (fp) {
        for (u64 i = 0; i < unique_n; i++) { fputs(lines[i], fp); }
        fclose(fp);
    }
    for (u64 i = 0; i < unique_n; i++) free(lines[i]);
    free(lines);
}


static ACFront ac_new_seeded(i64 sT, i64 p) {
    ACFront f;
    f.rc_buf = NULL; f.rc_len = 0; f.rc_cap = 0;
    f.idx = NULL; f.idx_n = 0;
    f.count = 0; f.popcount = 0; f.search_T = sT;
    /* Uniform seed model */
    u32 uniform[NSYMS];
    for (int i = 0; i < NSYMS; i++) uniform[i] = 1;
    fm_build(&f.gm, uniform);
    fm_build(&f.rm, uniform);
    fm_build(&f.enc_gm, uniform);
    fm_build(&f.enc_rm, uniform);
    /* Encode a single interval {p, 1} */
    i64 starts[1]; u64 runs[1];
    starts[0] = p; runs[0] = 1;
    ac_encode(&f, starts, runs, 1);
    f.popcount = 1;
    return f;
}

#if 0  /* v20: varint path no longer used, disabled */
typedef struct{u8*buf;u64 pos,cap;i64 last_end;int first;u64 count,pc;}SW;
static SW sw_new(u8*b,u64 c){return(SW){b,0,c,-1,1,0,0};}
static void sw_ensure(SW*w,u64 n){if(w->pos+n<=w->cap)return;while(w->pos+n>w->cap)w->cap*=2;w->buf=realloc(w->buf,w->cap);if(!w->buf){fprintf(stderr,"[FATAL]\n");exit(1);}}
static void sw_write(SW*w,i64 s,u64 l){if(!l)return;sw_ensure(w,20);if(w->first){w->pos+=vw(w->buf+w->pos,(u64)s);w->pos+=vw(w->buf+w->pos,l);w->first=0;}else{w->pos+=vw(w->buf+w->pos,(u64)(s-w->last_end));w->pos+=vw(w->buf+w->pos,l);}w->last_end=s+(i64)l;w->count++;w->pc+=l;}
static void sw_finish(SW*w){sw_ensure(w,2);if(!w->first)w->pos+=vw(w->buf+w->pos,0);}
static void front_shl_or(Front*f,i64 shift){
    u64 est=f->a_len*3+64;if(est<f->b_cap)est=f->b_cap;if(est>f->b_cap){f->b=realloc(f->b,est);f->b_cap=est;if(!f->b){fprintf(stderr,"[FATAL]\n");exit(1);}}
    u64 pa=0,pb=0;i64 a_s=-1;u64 a_l=0;int a_v=0;i64 b_s=-1;u64 b_l=0;int b_v=0;
    if(pa<f->a_len){a_s=(i64)vr64(f->a,&pa);a_l=vr64(f->a,&pa);a_v=1;}
    if(pb<f->a_len){b_s=(i64)vr64(f->a,&pb)+shift;b_l=vr64(f->a,&pb);b_v=1;}
    SW sw=sw_new(f->b,f->b_cap);
    #define ADV_A() do{if(pa<f->a_len){u64 g=vr64(f->a,&pa);if(!g)a_v=0;else{a_s+=a_l+g;a_l=(pa<f->a_len)?vr64(f->a,&pa):0;a_v=(a_l>0);}}else a_v=0;}while(0)
    #define ADV_B() do{if(pb<f->a_len){u64 g=vr64(f->a,&pb);if(!g)b_v=0;else{b_s+=b_l+g;b_l=(pb<f->a_len)?vr64(f->a,&pb):0;b_v=(b_l>0);}}else b_v=0;}while(0)
    while(b_v&&b_s+(i64)b_l<=0)ADV_B();if(b_v&&b_s<0){b_l+=b_s;b_s=0;}
    while(b_v&&b_s>f->search_T)ADV_B();
    while(a_v||b_v){i64 cs;u64 cl;
        if(a_v&&(!b_v||a_s<=b_s)){cs=a_s;cl=a_l;ADV_A();}
        else{cs=b_s;cl=b_l;
            if(cs>f->search_T){b_v=0;continue;}
            if(cs+(i64)cl>f->search_T+1)cl=(u64)(f->search_T+1-cs);
            ADV_B();
            while(b_v&&b_s>f->search_T)ADV_B();}
        i64 ce=cs+(i64)cl;if(ce>f->search_T+1)ce=f->search_T+1;
        while(a_v||b_v){if(a_v&&a_s<=ce){i64 ae=a_s+(i64)a_l;if(ae>ce)ce=ae;if(ce>f->search_T+1)ce=f->search_T+1;ADV_A();}
        else if(b_v&&b_s<=ce){i64 be=b_s+(i64)b_l;if(be>f->search_T+1)be=f->search_T+1;if(be>ce)ce=be;ADV_B();}else break;}
        if(ce<=cs)continue;
        sw_write(&sw,cs,(u64)(ce-cs));}
    sw_finish(&sw);f->b=sw.buf;f->b_cap=sw.cap;
    u8*t=f->a;f->a=f->b;f->b=t;u64 tl=f->a_cap;f->a_cap=f->b_cap;f->b_cap=tl;
    f->a_len=sw.pos;f->count=sw.count;f->popcount=sw.pc;
    if(f->b_cap>f->a_len*3+1024*1024){f->b_cap=f->a_len*2+1024*1024;u8*nb=realloc(f->b,f->b_cap);if(nb)f->b=nb;}
    #undef ADV_A
    #undef ADV_B
}

static void analyze_model(const u8*buf,u64 len,FModel*gm,FModel*rm){
    u32 gf[NSYMS]={0},rf[NSYMS]={0};u64 pos=0;vr64(buf,&pos);
    u64 run=vr64(buf,&pos);rf[run<=32?(int)(run-1):SYM_ESC]++;
    while(pos<len){u64 gap=vr64(buf,&pos);if(!gap){gf[SYM_END]++;break;}
        gf[gap<=32?(int)(gap-1):SYM_ESC]++;u64 r2=(pos<len)?vr64(buf,&pos):0;if(!r2)break;rf[r2<=32?(int)(r2-1):SYM_ESC]++;}
    gf[SYM_END]++;fm_build(gm,gf);fm_build(rm,rf);
}

static ACFront varint_to_ac(const u8*buf,u64 blen,u64 sc,i64 sT,const FModel*gm,const FModel*rm){
    i64*starts=malloc(sc*8);u64*runs=malloc(sc*8);u64 n=0,pop=0;
    u64 pos=0;i64 cur=(i64)vr64(buf,&pos);
    while(pos<blen){u64 run=vr64(buf,&pos);starts[n]=cur;runs[n]=run;pop+=run;n++;u64 gap=(pos<blen)?vr64(buf,&pos):0;if(!gap)break;cur+=(i64)run+(i64)gap;}
    ACFront f;f.rc_buf=NULL;f.rc_len=0;f.rc_cap=0;f.count=n;f.popcount=pop;f.search_T=sT;f.gm=*gm;f.rm=*rm;
    ac_encode(&f,starts,runs,n);free(starts);free(runs);return f;
}
#endif /* v20: end disabled varint path */

static u64 rng_s=12345;
static i64 rng(i64 R){rng_s^=rng_s<<13;rng_s^=rng_s>>7;rng_s^=rng_s<<17;return(i64)((rng_s>>1)%(u64)R)+1;}

/* === DFS reconstruction === */
/* Walk frontier files in reverse: at each step decide whether item[step]
 * was used to reach the current target. "Take" branch tries to include
 * item[step] if target - item[step] is reachable in frontier_{step-1}.
 * "Skip" branch continues without taking. Because items are sorted
 * ASCENDING and we walk from step=n-1 down to 0, "take" always tries
 * the largest remaining item first → biased toward smallest-k solutions.
 */
/* === Frontier LRU Cache for the walker ===
 *
 * The DFS walker repeatedly loads the same frontier_NNNN.bin files because
 * many DFS branches descend through the same step numbers. At R=1M the walk
 * does ~3500 nodes against ~700 distinct steps; at R=1B it can do millions
 * of node visits against ~700 steps. Caching the loaded ACFronts in memory
 * eliminates repeated file I/O + huff decode.
 *
 * Design:
 *   - Direct-indexed array `entries[step]`, since keys are dense integers.
 *   - Each cached entry has a refcount tracking live walker frames pointing
 *     at it. Refcounted entries are pinned and cannot be evicted.
 *   - LRU doubly-linked list orders entries by last-acquired time.
 *   - Eviction walks LRU tail looking for the oldest entry with refcount=0.
 *   - If all entries are pinned (rare), cache temporarily exceeds capacity.
 *
 * Walker contract change: walker_load_frontier now hands out a borrowed
 * pointer that the walker must NOT free. Instead it calls cache_release
 * when popping a frame.
 */
typedef struct CacheEntry {
    int step;
    int refcount;
    ACFront f;
    struct CacheEntry *lru_prev, *lru_next;
} CacheEntry;

typedef struct {
    CacheEntry **entries;   /* indexed by step; NULL = not cached */
    int n_steps;
    int capacity;           /* max entries (hard cap; 0 = ignore) */
    u64 capacity_bytes;     /* max bytes of rc_buf to cache (0 = ignore) */
    u64 cur_bytes;          /* current sum of cached rc_len */
    int n_entries;          /* current count of cached entries */
    CacheEntry *lru_head;   /* most recently used */
    CacheEntry *lru_tail;   /* least recently used */
    u64 hits, misses, evictions, peak_resident;
    u64 peak_bytes;
} FrontierCache;

static void fc_init(FrontierCache *c, int n_steps, int capacity, u64 capacity_bytes) {
    c->entries = calloc(n_steps + 1, sizeof(CacheEntry*));
    c->n_steps = n_steps + 1;
    c->capacity = capacity;
    c->capacity_bytes = capacity_bytes;
    c->cur_bytes = 0;
    c->n_entries = 0;
    c->lru_head = c->lru_tail = NULL;
    c->hits = c->misses = c->evictions = c->peak_resident = 0;
    c->peak_bytes = 0;
}

static void fc_lru_unlink(FrontierCache *c, CacheEntry *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else c->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else c->lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void fc_lru_push_head(FrontierCache *c, CacheEntry *e) {
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

static void fc_evict_one(FrontierCache *c) {
    /* Walk LRU from tail, find first unrefed entry */
    CacheEntry *e = c->lru_tail;
    while (e && e->refcount > 0) e = e->lru_prev;
    if (!e) return;  /* all pinned, can't evict */
    fc_lru_unlink(c, e);
    c->entries[e->step] = NULL;
    u64 freed = e->f.rc_len;
    frontier_free(&e->f);
    free(e);
    c->n_entries--;
    if (c->cur_bytes >= freed) c->cur_bytes -= freed; else c->cur_bytes = 0;
    c->evictions++;
}

/* Acquire a frontier for `step`. Returns a borrowed pointer; caller must
 * call fc_release when done. */
static ACFront *fc_acquire(FrontierCache *c, int step, const char *dir) {
    if (step < 0 || step >= c->n_steps) return NULL;
    CacheEntry *e = c->entries[step];
    if (e) {
        c->hits++;
        e->refcount++;
        fc_lru_unlink(c, e);
        fc_lru_push_head(c, e);
        return &e->f;
    }
    /* Miss: load from disk */
    c->misses++;
    e = calloc(1, sizeof(CacheEntry));
    e->step = step;
    e->refcount = 1;
    char path[2048];
    snprintf(path, sizeof(path), "%s/frontier_%04d.bin", dir, step);
    if (!frontier_load(&e->f, path)) {
        free(e);
        return NULL;
    }
    c->entries[step] = e;
    fc_lru_push_head(c, e);
    c->n_entries++;
    c->cur_bytes += e->f.rc_len;
    if ((u64)c->n_entries > c->peak_resident) c->peak_resident = c->n_entries;
    if (c->cur_bytes > c->peak_bytes) c->peak_bytes = c->cur_bytes;
    /* Evict down to capacity if possible. Honor whichever limit is tighter. */
    while ((c->capacity > 0 && c->n_entries > c->capacity) ||
           (c->capacity_bytes > 0 && c->cur_bytes > c->capacity_bytes)) {
        int before = c->n_entries;
        fc_evict_one(c);
        if (c->n_entries == before) break;  /* all pinned */
    }
    return &e->f;
}

static void fc_release(FrontierCache *c, ACFront *f) {
    if (!f) return;
    /* The ACFront is embedded in a CacheEntry. Find the entry by walking
     * (rare case where we don't know step) — actually, we can recover by
     * pointer arithmetic: f is at offsetof(CacheEntry, f) inside e. */
    CacheEntry *e = (CacheEntry *)((char *)f - offsetof(CacheEntry, f));
    if (e->refcount > 0) e->refcount--;
}

static void fc_free(FrontierCache *c) {
    for (int i = 0; i < c->n_steps; i++) {
        if (c->entries[i]) {
            frontier_free(&c->entries[i]->f);
            free(c->entries[i]);
        }
    }
    free(c->entries);
    c->entries = NULL;
}



/* Walker state. The DFS keeps a stack of WalkFrames; this struct holds
 * everything that's invariant across the walk. */
typedef struct {
    i64 *items;            /* n values, sorted ascending */
    int n;
    i64 search_T;
    int flipped;           /* 1 if T > total/2, meaning walker found complement-side subsets */
    const char *dir;       /* frontier files directory */
    SolWriter *sw;
    i64 *taken_values;     /* current path of taken item values (stack) */
    int taken_depth;
    u64 nodes_visited;
    u64 nodes_forced_take;
    u64 nodes_forced_skip;
    u64 nodes_branching;
    u64 nodes_dead;
    double walk_start;
    FrontierCache *cache;  /* may be NULL → no caching, fall back to direct load */
    int random_order;      /* 1 = randomize TAKE/SKIP order at branching nodes */
    u64 rng_state;         /* LCG state for random_order (seeded from CLI seed) */
    /* Storage for the seed (step==-1) frontier so we don't have to special-
     * case it in the cache. The walker re-uses this single instance. */
    ACFront seed_front;
    int seed_initialized;
} Walker;

/* Acquire the frontier for a given step. Returns a borrowed pointer that
 * the caller MUST release via walker_release_frontier. The returned ACFront
 * is owned by the cache (or by w->seed_front for step==-1).
 *
 * Returns NULL on file load failure. */
static ACFront *walker_acquire_frontier(Walker *w, int step) {
    if (step < 0) {
        if (!w->seed_initialized) {
            w->seed_front = ac_new_seeded(w->search_T, 0);
            w->seed_initialized = 1;
        }
        return &w->seed_front;
    }
    if (w->cache) {
        return fc_acquire(w->cache, step, w->dir);
    }
    /* No cache: load into a one-shot heap allocation. The release function
     * will free it. We tag this by storing in a sentinel — but since the
     * cache path uses pointer arithmetic to recover the CacheEntry, the
     * non-cache path needs a different lifecycle. To keep the call sites
     * uniform, we always have a cache. The default capacity should be set
     * by the caller before calling walker_dfs. */
    return NULL;
}

static void walker_release_frontier(Walker *w, ACFront *f, int step) {
    if (!f) return;
    if (step < 0) return;  /* seed front is owned by walker, never released */
    if (w->cache) fc_release(w->cache, f);
}

/* Iterative DFS walker. Recursion would blow the stack at large n because
 * each frame holds an ACFront with ~64 KB of HModel structs.  Instead:
 * explicit per-depth state on the heap.
 *
 * Forced-decision optimization: at each frame entry, check both can_take and
 * can_skip via ac_contains. If only one is viable, COLLAPSE the decision into
 * the same frame slot rather than pushing a child frame. The frame's
 * took_count tracks how many values it has pushed onto taken_values, so on
 * pop we restore taken_depth correctly even after multiple in-place
 * collapses.
 *
 * Empirically, 75-87% of decisions are forced, so this dramatically reduces
 * the number of stack frames pushed and the per-frame overhead. */
typedef struct {
    int step;           /* current item index */
    i64 target;         /* remaining target */
    int phase;          /* 0 = entry/classify, 1 = deferred branch pending */
    int took_count;     /* number of values pushed onto taken_values for this frame */
    ACFront *prev;      /* borrowed from cache; NULL if not yet acquired */
    int prev_step;      /* step number prev was loaded for (= owning frame's step - 1) */
    int deferred_take;  /* when phase==1: 1 if TAKE is deferred, 0 if SKIP is deferred */
    i64 deferred_target;/* target to use if deferred TAKE is executed (= original_target - vv) */
} WalkFrame;

static void walker_dfs(Walker *w, int start_step, i64 start_target) {
    int cap = start_step + 4;
    if (cap < 8) cap = 8;
    WalkFrame *stk = calloc(cap, sizeof(WalkFrame));
    int top = 0;
    stk[0].step = start_step;
    stk[0].target = start_target;
    stk[0].phase = 0;
    stk[0].took_count = 0;
    stk[0].prev = NULL;
    stk[0].prev_step = -2;

    while (top >= 0) {
        /* Termination: in find-k mode, stop when every requested k has reached
         * the per-k cap (sw->per_k_limit). Otherwise, stop at --limit total.
         * Also stop if the search space is exhausted of unique solutions. */
        if (w->sw->exhausted) break;
        if (w->sw->find_k_n > 0) {
            int all_capped = 1;
            for (int i = 0; i < w->sw->find_k_n; i++) {
                if (w->sw->find_k_found[i] < w->sw->per_k_limit) { all_capped = 0; break; }
            }
            if (all_capped) break;
        } else {
            if (w->sw->count >= w->sw->limit) break;
        }
        WalkFrame *f = &stk[top];

        /* Base case: step < 0 means we've decided every item */
        if (f->step < 0) {
            if (f->target == 0) {
                solw_emit_with_complement(w->sw, w->taken_values, w->taken_depth,
                                          w->items, w->n, w->flipped);
            }
            w->taken_depth -= f->took_count;
            top--;
            continue;
        }

        if (f->phase == 0) {
            /* Entry / classify. Acquire prev if needed. */
            w->nodes_visited++;
            if (f->prev == NULL) {
                f->prev = walker_acquire_frontier(w, f->step - 1);
                f->prev_step = f->step - 1;
                if (!f->prev) {
                    w->taken_depth -= f->took_count;
                    top--;
                    continue;
                }
            }

            i64 vv = w->items[f->step];
            i64 nt = f->target - vv;
            int can_take = (nt >= 0 && ac_contains(f->prev, nt));
            int can_skip = ac_contains(f->prev, f->target);

            if (can_take && can_skip) {
                /* Branching: push one child, defer the other for phase==1.
                 * Default: TAKE first (child), SKIP deferred (parent phase 1).
                 * With --random-order: flip a coin to decide which goes first.
                 * Release parent's prev across child recursion to avoid pinning
                 * giant frontiers in cache. Parent will re-acquire on phase 1. */
                w->nodes_branching++;
                int take_first = 1;
                if (w->random_order) {
                    /* xorshift64 step */
                    w->rng_state ^= w->rng_state << 13;
                    w->rng_state ^= w->rng_state >> 7;
                    w->rng_state ^= w->rng_state << 17;
                    take_first = (int)(w->rng_state & 1);
                }
                f->phase = 1;
                if (take_first) {
                    /* TAKE as child, SKIP deferred on parent */
                    w->taken_values[w->taken_depth++] = vv;
                    f->deferred_take = 0;      /* parent will execute SKIP in phase 1 */
                    f->deferred_target = 0;    /* unused for SKIP */
                } else {
                    /* SKIP as child, TAKE deferred on parent */
                    f->deferred_take = 1;
                    f->deferred_target = nt;
                }
                walker_release_frontier(w, f->prev, f->prev_step);
                f->prev = NULL;
                top++;
                if (top >= cap) {
                    int new_cap = cap * 2;
                    stk = realloc(stk, new_cap * sizeof(WalkFrame));
                    memset(stk + cap, 0, (new_cap - cap) * sizeof(WalkFrame));
                    cap = new_cap;
                    f = &stk[top - 1];
                }
                stk[top].step = f->step - 1;
                stk[top].target = take_first ? nt : f->target;
                stk[top].phase = 0;
                stk[top].took_count = take_first ? 1 : 0;
                stk[top].prev = NULL;
                stk[top].prev_step = -2;
                stk[top].deferred_take = 0;
                stk[top].deferred_target = 0;
                continue;
            } else if (can_take) {
                /* Forced TAKE: collapse in place */
                w->nodes_forced_take++;
                w->taken_values[w->taken_depth++] = vv;
                walker_release_frontier(w, f->prev, f->prev_step);
                f->prev = NULL;
                f->step -= 1;
                f->target = nt;
                f->phase = 0;
                f->took_count += 1;
                continue;
            } else if (can_skip) {
                /* Forced SKIP: collapse in place */
                w->nodes_forced_skip++;
                walker_release_frontier(w, f->prev, f->prev_step);
                f->prev = NULL;
                f->step -= 1;
                f->phase = 0;
                continue;
            } else {
                w->nodes_dead++;
                walker_release_frontier(w, f->prev, f->prev_step);
                f->prev = NULL;
                w->taken_depth -= f->took_count;
                top--;
                continue;
            }
        }

        if (f->phase == 1) {
            /* Execute the deferred branch. By default (or if random_order chose
             * TAKE first), we deferred SKIP — just move to the next step.
             * If random_order chose SKIP first, we deferred TAKE — push the
             * item value and update target before moving on. */
            walker_release_frontier(w, f->prev, f->prev_step);
            f->prev = NULL;
            if (f->deferred_take) {
                w->taken_values[w->taken_depth++] = w->items[f->step];
                f->target = f->deferred_target;
                f->took_count += 1;
                f->deferred_take = 0;
            }
            f->step -= 1;
            f->phase = 0;
            continue;
        }
    }
    /* Clean up any remaining frames (if we early-exited on limit) */
    for (int i = 0; i <= top; i++) {
        if (stk[i].prev) walker_release_frontier(w, stk[i].prev, stk[i].prev_step);
    }
    free(stk);
}

int main(int argc,char**argv){
    /* Preprocess argv: split any `--flag=value` argument into two separate
     * argv slots so the space-separated parser below handles both forms. */
    {
        char **nargv = malloc((argc * 2 + 1) * sizeof(char*));
        int ni = 0;
        nargv[ni++] = argv[0];
        for (int i = 1; i < argc; i++) {
            char *eq = (argv[i][0] == '-' && argv[i][1] == '-') ? strchr(argv[i], '=') : NULL;
            if (eq) {
                size_t flag_len = eq - argv[i];
                char *flag = malloc(flag_len + 1);
                memcpy(flag, argv[i], flag_len);
                flag[flag_len] = 0;
                nargv[ni++] = flag;
                nargv[ni++] = eq + 1;
            } else {
                nargv[ni++] = argv[i];
            }
        }
        argv = nargv;
        argc = ni;
    }
    int n=50;i64 R=100000;int plant_k=-1;i64 user_T=-1;int seed=12345,quiet=0;i64 max_mem_mb=4096;
    int do_recon=0;i64 sol_limit=1000;
    int cache_capacity=0;
    i64 cache_mb=0;
    int do_probe=0;
    const char *out_path="solutions.txt";
    const char *frontier_dir="frontiers";
    int find_k_arr[256]; int find_k_n=0;
    i64 per_k_limit=-1;
    const char *items_file=NULL;
    const char *items_inline=NULL;
    const char *recon_from_dir=NULL;
    int stop_on_target=0;
    int random_order=0;
    for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--recon-from")){recon_from_dir=argv[++i];do_recon=1;}
        else if(!strcmp(argv[i],"--stop-on-target")){stop_on_target=1;do_recon=1;}
        else if(!strcmp(argv[i],"--random-order")){random_order=1;}
        else if(!strcmp(argv[i],"--n"))n=atoi(argv[++i]);else if(!strcmp(argv[i],"--R"))R=atoll(argv[++i]);
        else if(!strcmp(argv[i],"--k"))plant_k=atoi(argv[++i]);else if(!strcmp(argv[i],"--T"))user_T=atoll(argv[++i]);
        else if(!strcmp(argv[i],"--seed"))seed=atoi(argv[++i]);else if(!strcmp(argv[i],"--quiet"))quiet=1;
        else if(!strcmp(argv[i],"--mem"))max_mem_mb=atoll(argv[++i]);else if(!strcmp(argv[i],"--recon"))do_recon=1;
        else if(!strcmp(argv[i],"--probe")){do_recon=1;do_probe=1;}
        else if(!strcmp(argv[i],"--limit"))sol_limit=atoll(argv[++i]);
        else if(!strcmp(argv[i],"--per-k-limit"))per_k_limit=atoll(argv[++i]);
        else if(!strcmp(argv[i],"--items-file"))items_file=argv[++i];
        else if(!strcmp(argv[i],"--items"))items_inline=argv[++i];
        else if(!strcmp(argv[i],"--cache"))cache_capacity=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--cache-mb"))cache_mb=atoll(argv[++i]);
        else if(!strcmp(argv[i],"--out"))out_path=argv[++i];
        else if(!strcmp(argv[i],"--frontier-dir"))frontier_dir=argv[++i];
        else if(!strcmp(argv[i],"--find-k")){
            do_recon=1;
            const char *s=argv[++i];
            while(*s && find_k_n<256){
                while(*s==' '||*s==',') s++;
                if(!*s) break;
                find_k_arr[find_k_n++]=atoi(s);
                while(*s && *s!=',' && *s!=' ') s++;
            }
        }}
    rng_s=(u64)seed;
    i64 *items = NULL;
    i64 T = 0, total = 0, anti = 0, search_T = 0;
    char run_dir[1200];
    int loaded_from_meta = 0;
    i64 saved_search_T = 0;
    int saved_planted_k = -1;
    i64 saved_planted_T = 0;

    if(recon_from_dir){
        char meta_path[1300];
        snprintf(meta_path,sizeof(meta_path),"%s/meta.txt",recon_from_dir);
        int mn=0,mseed=0; i64 mR=0;
        if(!meta_load(meta_path,&mn,&mR,&mseed,&saved_planted_k,
                      &saved_planted_T,&total,&saved_search_T,&items)){
            fprintf(stderr,"failed to load meta from %s\n",meta_path);return 1;
        }
        n=mn; R=mR; seed=mseed;
        snprintf(run_dir,sizeof(run_dir),"%s",recon_from_dir);
        loaded_from_meta=1; do_recon=1;
        if(user_T>=0) T=user_T; else T=saved_planted_T;
        anti=total-T; search_T=T<anti?T:anti;
        if(search_T>saved_search_T){
            printf("Target not reachable: requested search_T=%lld exceeds saved search_T=%lld\n",
                   (long long)search_T,(long long)saved_search_T);
            free(items); return 0;
        }
        printf("Loaded run from %s (n=%d, R=%lld, seed=%d)\n",run_dir,n,(long long)R,seed);
        printf("  planted_T=%lld, saved search_T=%lld\n",(long long)saved_planted_T,(long long)saved_search_T);
        if(user_T>=0) printf("  override T=%lld -> search_T=%lld\n",(long long)T,(long long)search_T);
    } else {
        if(items_file){
            FILE *fp=fopen(items_file,"r");
            if(!fp){fprintf(stderr,"could not open items file %s\n",items_file);return 1;}
            int cap=1024; items=malloc(cap*8); n=0;
            char buf[64];
            while(fgets(buf,sizeof(buf),fp)){
                char *p=buf; while(*p==' '||*p=='\t')p++;
                if(*p=='\n'||*p=='#'||*p==0)continue;
                if(n>=cap){cap*=2;items=realloc(items,cap*8);}
                items[n++]=atoll(p);
            }
            fclose(fp);
            printf("Loaded %d items from %s\n",n,items_file);
        } else if(items_inline){
            /* Parse comma-separated items from --items "v1,v2,v3,..." */
            int cap=1024; items=malloc(cap*8); n=0;
            const char *s=items_inline;
            while(*s){
                while(*s==' '||*s==','||*s=='\t') s++;
                if(!*s) break;
                if(n>=cap){cap*=2;items=realloc(items,cap*8);}
                items[n++]=strtoll(s,(char**)&s,10);
            }
            printf("Loaded %d items from --items\n",n);
        } else {
            items=malloc(n*8);
            for(int i=0;i<n;i++)items[i]=rng(R);
        }
        if(plant_k>0){T=0;for(int i=n-1;i>0;i--){int j=(int)(rng(i+1)-1);i64 t=items[i];items[i]=items[j];items[j]=t;}for(int i=0;i<plant_k&&i<n;i++)T+=items[i];printf("Planted k=%d, T=%lld\n",plant_k,(long long)T);}
        else if(user_T>=0)T=user_T;else{i64 tot=0;for(int i=0;i<n;i++)tot+=items[i];T=tot/3;}
        total=0;for(int i=0;i<n;i++)total+=items[i];anti=total-T;search_T=T<anti?T:anti;
        /* ASCENDING sort */
        int cmp_a(const void*a,const void*b){i64 x=*(i64*)a,y=*(i64*)b;return(x>y)-(x<y);}
        qsort(items,n,8,cmp_a);

        if(do_recon){
            time_t now=time(NULL);
            struct tm *tm=localtime(&now);
            char stamp[64];
            strftime(stamp,sizeof(stamp),"%Y%m%d_%H%M%S",tm);
            snprintf(run_dir,sizeof(run_dir),"%s/run_%s_s%d",frontier_dir,stamp,seed);
            char cmd[1400];
            snprintf(cmd,sizeof(cmd),"mkdir -p %s",run_dir);
            if(system(cmd)!=0){fprintf(stderr,"failed to create run dir %s\n",run_dir);return 1;}
            char meta_path[1300];
            snprintf(meta_path,sizeof(meta_path),"%s/meta.txt",run_dir);
            if(!meta_save(meta_path,n,R,seed,plant_k,T,total,search_T,items)){
                fprintf(stderr,"failed to write meta to %s\n",meta_path);return 1;
            }
            printf("Run dir: %s\n",run_dir);
        }
    }
    char mb1[32],mb2[32];
    printf("CRISP v24 (single-pass Huffman, recon)\n");
    printf("n=%d R=%lld T=%lld search_T=%lld\n",n,(long long)R,(long long)T,(long long)search_T);
    if(search_T != T) printf("  note: T > total/2, searching for complement (total-T=%lld). Solutions will be flipped to sum to T.\n",(long long)search_T);
    printf("bitset equiv = %s\n",fmt_bytes(search_T/8+1,mb1));
    printf("memory limit: %lld MB\n", (long long)max_mem_mb);
    if(do_recon) printf("reconstruction enabled: --limit=%lld --out=%s\n",(long long)sol_limit,out_path);
    printf("\n");

    double t0=now_ms();int found=-1,fi=0;
    ACFront fwd;
    if(loaded_from_meta){
        /* Skip build; find highest saved frontier and defer to walker. */
        fi = find_max_frontier_step(run_dir) + 1;
        if(fi<=0){
            fprintf(stderr,"no frontier files found in %s\n",run_dir);
            free(items); return 1;
        }
        printf("Skipping build; resuming recon from step %d\n",fi);
        fwd = ac_new_seeded(search_T,0);
        found = fi - 1;
        goto recon_phase;
    }
    fwd = ac_new_seeded(search_T, 0);
    /* Memory band tracking: emit a special log line every time RSS or VmSize
     * crosses a 500 MB boundary, even between scheduled step logs. */
    const u64 MEM_BAND = 500ULL * 1024 * 1024;
    u64 last_rss_band = 0;
    u64 last_vsize_band = 0;
    for(;fi<n;fi++){
        ac_shl_or(&fwd, items[fi]);
        mem_track(0);
        MemInfo mi = proc_mem();
        u64 rss_now = mi.rss;
        /* Save frontier for reconstruction */
        if(do_recon){
            char path[2048];
            snprintf(path,sizeof(path),"%s/frontier_%04d.bin",run_dir,fi);
            if(!frontier_save(&fwd,path,(u64)fi)){
                fprintf(stderr,"frontier save failed at step %d\n",fi);
                break;
            }
        }
        /* Memory band trigger: log whenever RSS or VmSize crosses a
         * MEM_BAND boundary (in either direction — but typically up). */
        u64 rss_band = mi.rss / MEM_BAND;
        u64 vsize_band = mi.vsize / MEM_BAND;
        if(rss_band != last_rss_band || vsize_band != last_vsize_band){
            char m_rss[32], m_vs[32], m_vp[32];
            printf("  ▲ MEM step %d │ rss=%s │ vsize=%s │ vpeak=%s │ segs=%llu │ huff=%s\n",
                fi+1,
                fmt_bytes(mi.rss, m_rss),
                fmt_bytes(mi.vsize, m_vs),
                fmt_bytes(mi.vpeak, m_vp),
                (unsigned long long)fwd.count,
                fmt_bytes(fwd.rc_len, mb1));
            fflush(stdout);
            last_rss_band = rss_band;
            last_vsize_band = vsize_band;
        }
        if(!quiet && ((fi+1)%10==0 || fi<5)){
            char m_vs_step[32];
            printf("  step %4d/%d │ item=%9lld │ segs=%9llu │ huff=%s │ rss=%s │ vsize=%s │ %.0fms\n",
                fi+1, n, (long long)items[fi], (unsigned long long)fwd.count,
                fmt_bytes(fwd.rc_len, mb1), fmt_bytes(rss_now, mb2),
                fmt_bytes(mi.vsize, m_vs_step), now_ms()-t0);
            fflush(stdout);
        }
        if(found<0 && ac_contains(&fwd, search_T)){
            found = fi;
            printf("\n  ★ T reached at step %d after %.0fms (segs=%llu huff=%s)\n",
                found+1, now_ms()-t0, (unsigned long long)fwd.count, fmt_bytes(fwd.rc_len, mb1));
            printf("    RSS: %s\n", fmt_bytes(proc_rss(), mb1));
            fflush(stdout);
            if(stop_on_target){
                printf("    --stop-on-target: ending build, proceeding to reconstruction\n");
                fflush(stdout);
                fi++;
                break;
            }
        }
        u64 mem_mb = rss_now/(1024*1024);
        if((i64)mem_mb > max_mem_mb){ printf("\n  ✗ Memory limit: RSS=%s exceeds %lld MB\n", fmt_bytes(rss_now, mb1), (long long)max_mem_mb); break; }
    }
    double total_ms = now_ms() - t0;

    printf("\n═══ SUMMARY ═══\n");
    printf("  steps completed:  %d/%d\n", fi, n);
    if(found>=0) printf("  T first reached: step %d\n", found+1);
    else         printf("  T never reached\n");
    printf("  total time:       %.0fms\n", total_ms);
    printf("  final huff: %s (%llu segs, popcount=%llu)\n",
        fmt_bytes(fwd.rc_len, mb1), (unsigned long long)fwd.count,
        (unsigned long long)fwd.popcount);
    {
        MemInfo mi = proc_mem();
        printf("  ── memory ──\n");
        printf("    final RSS:    %s   (kernel resident set, our process only)\n",
            fmt_bytes(mi.rss, mb1));
        printf("    peak  RSS:    %s   (high water of resident set)\n",
            fmt_bytes(mi.hwm, mb1));
        printf("    final VmSize: %s   (full virtual address space)\n",
            fmt_bytes(mi.vsize, mb1));
        printf("    peak  VmSize: %s   (closest to what host task mgr shows)\n",
            fmt_bytes(mi.vpeak, mb1));
    }
    printf("  ── timing breakdown ──\n");
    printf("    pass1 (decode+merge+count):    %.0f ms (%.0f%%)\n",
        t_pass1_ns/1e6, 100.0*t_pass1_ns/(total_ms*1e6));
    printf("    model rebuild:                  %.0f ms (%.0f%%)\n",
        t_model_ns/1e6, 100.0*t_model_ns/(total_ms*1e6));
    printf("    encode buf alloc:               %.0f ms (%.0f%%)\n",
        t_alloc_ns/1e6, 100.0*t_alloc_ns/(total_ms*1e6));
    printf("    pass2 (decode+merge+encode):    %.0f ms (%.0f%%)\n",
        t_pass2_ns/1e6, 100.0*t_pass2_ns/(total_ms*1e6));
    /* === Alphabet stability probe — list unique gap values per frontier === */
    if(do_probe && fi >= 4){
        printf("\n═══ ALPHABET PROBE — unique gap values per frontier ═══\n");
        printf("  format: step | n_unique | unique gaps (sorted)\n\n");
        for(int s = 1; s < fi; s += (fi/20 > 0 ? fi/20 : 1)){
            ACFront f;
            char path[2048];
            snprintf(path, sizeof(path), "%s/frontier_%04d.bin", run_dir, s);
            if(!frontier_load(&f, path)) continue;
            if(f.popcount > 2000000){
                printf("  step %4d: too dense (popcount %llu), skip\n",
                    s, (unsigned long long)f.popcount);
                frontier_free(&f);
                continue;
            }
            IvArrays ia = ac_decode(&f);
            i64 *P = malloc(f.popcount * sizeof(i64));
            u64 pp = 0;
            for(u64 j=0;j<ia.count;j++)
                for(u64 k=0;k<ia.runs[j];k++) P[pp++] = ia.starts[j] + (i64)k;

            i64 *gaps = malloc(f.popcount * sizeof(i64));
            u64 ngaps = 0;
            for(u64 j = 0; j+1 < f.popcount; j++){
                i64 g = P[j+1] - P[j];
                if(g > 0) gaps[ngaps++] = g;
            }
            for(u64 j = 1; j < ngaps; j++){
                i64 v = gaps[j]; u64 k = j;
                while(k > 0 && gaps[k-1] > v){ gaps[k]=gaps[k-1]; k--; }
                gaps[k] = v;
            }
            i64 ug[4096]; u64 n_ug = 0;
            for(u64 j = 0; j < ngaps && n_ug < 4096; j++)
                if(n_ug == 0 || ug[n_ug-1] != gaps[j]) ug[n_ug++] = gaps[j];

            printf("  step %4d  pop=%-7llu  intervals=%-6llu  n_unique=%llu  gaps={",
                s, (unsigned long long)f.popcount,
                (unsigned long long)f.count, (unsigned long long)n_ug);
            for(u64 j = 0; j < n_ug && j < 30; j++){
                printf("%lld", (long long)ug[j]);
                if(j+1 < n_ug && j+1 < 30) printf(",");
            }
            if(n_ug > 30) printf(",...");
            printf("}\n");

            free(gaps); free(P);
            free(ia.starts); free(ia.runs);
            frontier_free(&f);
        }
        printf("\n");
    }

    /* === Frontier diff probe — gap-set vs item pair diffs === */
    if(do_probe && fi >= 4){
        printf("\n═══ DIFF PROBE — GAP-SET vs ITEM-PAIR-DIFF ANALYSIS ═══\n\n");
        fflush(stdout);

        int probe_steps[] = {3, 5, 7, fi/4, fi/2, fi*2/3, fi-2};
        int n_probes = 7;
        for(int pi = 0; pi < n_probes; pi++){
            int s = probe_steps[pi];
            if(s < 1 || s >= fi) continue;
            ACFront f;
            char path[2048];
            snprintf(path, sizeof(path), "%s/frontier_%04d.bin", run_dir, s);
            if(!frontier_load(&f, path)) continue;
            if(f.popcount > 50000){
                printf("step %d: too dense (popcount %llu), skip\n", s, (unsigned long long)f.popcount);
                frontier_free(&f);
                continue;
            }
            IvArrays ia = ac_decode(&f);
            /* popcount should match sum of run lengths now that the
             * checkpoint bug is gone. Use stored value directly. */
            i64 *P = malloc(f.popcount * sizeof(i64));
            u64 pp = 0;
            for(u64 j=0;j<ia.count;j++)
                for(u64 k=0;k<ia.runs[j];k++) P[pp++] = ia.starts[j] + (i64)k;
            /* Use the actual decoded count from now on */
            u64 popcount = pp;

            /* Collect ALL gap values (consecutive only — distance-1) */
            i64 *gaps = malloc(popcount * sizeof(i64));
            u64 ngaps = 0;
            for(u64 j = 0; j+1 < popcount; j++){
                i64 g = P[j+1] - P[j];
                if(g > 0) gaps[ngaps++] = g;
            }

            /* Sort gaps and dedupe */
            for(u64 j = 1; j < ngaps; j++){
                i64 v = gaps[j]; u64 k = j;
                while(k > 0 && gaps[k-1] > v){ gaps[k]=gaps[k-1]; k--; }
                gaps[k] = v;
            }
            i64 *ugaps = malloc((ngaps+1) * sizeof(i64));
            u64 n_ugaps = 0;
            for(u64 j = 0; j < ngaps; j++)
                if(n_ugaps == 0 || ugaps[n_ugaps-1] != gaps[j])
                    ugaps[n_ugaps++] = gaps[j];

            /* Compute all pairwise item differences */
            int n_pairs = n*(n-1)/2;
            i64 *pair_diffs = malloc(n_pairs * sizeof(i64));
            int npd = 0;
            for(int i=0;i<n;i++)
                for(int j=i+1;j<n;j++)
                    pair_diffs[npd++] = items[j] - items[i];

            /* For each unique gap value, check if it equals some pair diff */
            u64 ugap_eq_pair_diff = 0;
            for(u64 j = 0; j < n_ugaps; j++){
                for(int k=0;k<npd;k++){
                    if(pair_diffs[k] == ugaps[j]){ ugap_eq_pair_diff++; break; }
                }
            }

            /* Build hash set of frontier positions */
            u64 hashcap = 1;
            while(hashcap < popcount * 4) hashcap <<= 1;
            i64 *hash = malloc(hashcap * sizeof(i64));
            for(u64 j = 0; j < hashcap; j++) hash[j] = -1;
            for(u64 j = 0; j < popcount; j++){
                u64 h = ((u64)P[j] * 2654435769ULL) & (hashcap - 1);
                while(hash[h] >= 0) h = (h + 1) & (hashcap - 1);
                hash[h] = P[j];
            }

            /* For each pair diff, count "swaps realized" */
            u64 *swap_counts = calloc(npd, sizeof(u64));
            for(int k = 0; k < npd; k++){
                i64 D = pair_diffs[k];
                u64 c = 0;
                for(u64 j = 0; j < popcount; j++){
                    i64 q = P[j] + D;
                    u64 h = ((u64)q * 2654435769ULL) & (hashcap - 1);
                    while(hash[h] >= 0){
                        if(hash[h] == q){ c++; break; }
                        h = (h + 1) & (hashcap - 1);
                    }
                }
                swap_counts[k] = c;
            }

            /* Build subset sums of unique gaps (cap at first 16 to keep 2^16 manageable) */
            int max_g = 16;
            int actual_g = (int)(n_ugaps < (u64)max_g ? n_ugaps : (u64)max_g);
            int max_masks = 1 << actual_g;
            i64 *subset_sums = NULL;
            int n_ss = 0;
            if(actual_g > 0){
                subset_sums = malloc(max_masks * sizeof(i64));
                for(int m = 1; m < max_masks; m++){
                    i64 s2 = 0;
                    for(int b = 0; b < actual_g; b++) if(m & (1<<b)) s2 += ugaps[b];
                    subset_sums[n_ss++] = s2;
                }
                /* sort */
                for(int j2 = 1; j2 < n_ss; j2++){
                    i64 v2 = subset_sums[j2]; int k2 = j2;
                    while(k2 > 0 && subset_sums[k2-1] > v2){ subset_sums[k2]=subset_sums[k2-1]; k2--; }
                    subset_sums[k2] = v2;
                }
            }

            /* Cross-tabulate: pair-diff matches subset-sum × pair has realized swap */
            u64 ss_yes_swap_yes = 0;
            u64 ss_yes_swap_no  = 0;
            u64 ss_no_swap_yes  = 0;
            u64 ss_no_swap_no   = 0;
            for(int k = 0; k < npd; k++){
                int hit = 0;
                if(n_ss > 0){
                    i64 want = pair_diffs[k];
                    int lo2 = 0, hi2 = n_ss;
                    while(lo2 < hi2){
                        int mm = (lo2+hi2)/2;
                        if(subset_sums[mm] < want) lo2 = mm+1; else hi2 = mm;
                    }
                    if(lo2 < n_ss && subset_sums[lo2] == want) hit = 1;
                }
                int swap = (swap_counts[k] > 0);
                if(hit && swap)       ss_yes_swap_yes++;
                else if(hit && !swap) ss_yes_swap_no++;
                else if(!hit && swap) ss_no_swap_yes++;
                else                  ss_no_swap_no++;
            }
            if(subset_sums) free(subset_sums);

            printf("step %d  popcount=%llu  intervals=%llu  unique_gaps=%llu  pair_diffs=%d\n",
                s, (unsigned long long)f.popcount, (unsigned long long)f.count,
                (unsigned long long)n_ugaps, npd);
            printf("  unique gaps that match SOME pair diff: %llu/%llu (%.0f%%)\n",
                (unsigned long long)ugap_eq_pair_diff, (unsigned long long)n_ugaps,
                n_ugaps?100.0*ugap_eq_pair_diff/n_ugaps:0);
            printf("  pair diffs cross-tab against gap-subset-sum match × realized swap:\n");
            printf("                          subset hit │ subset miss │ total\n");
            printf("    swap realized:    %10llu │ %11llu │ %llu\n",
                (unsigned long long)ss_yes_swap_yes,
                (unsigned long long)ss_no_swap_yes,
                (unsigned long long)(ss_yes_swap_yes + ss_no_swap_yes));
            printf("    no swap:          %10llu │ %11llu │ %llu\n",
                (unsigned long long)ss_yes_swap_no,
                (unsigned long long)ss_no_swap_no,
                (unsigned long long)(ss_yes_swap_no + ss_no_swap_no));
            printf("    total:            %10llu │ %11llu │ %d\n",
                (unsigned long long)(ss_yes_swap_yes + ss_yes_swap_no),
                (unsigned long long)(ss_no_swap_yes + ss_no_swap_no),
                npd);
            u64 ss_yes_total = ss_yes_swap_yes + ss_yes_swap_no;
            u64 swap_total   = ss_yes_swap_yes + ss_no_swap_yes;
            if(ss_yes_total > 0){
                printf("    P(swap | subset hit)  = %.0f%%   (precision)\n",
                    100.0*ss_yes_swap_yes/ss_yes_total);
            }
            if(swap_total > 0){
                printf("    P(subset hit | swap)  = %.0f%%   (recall)\n",
                    100.0*ss_yes_swap_yes/swap_total);
            }
            /* Random baseline: P(swap) overall */
            printf("    P(swap) overall       = %.0f%%   (random baseline)\n",
                100.0*swap_total/npd);
            printf("\n");

            free(hash);
            free(swap_counts);
            free(pair_diffs);
            free(ugaps);
            free(gaps);
            free(P);
            free(ia.starts); free(ia.runs);
            frontier_free(&f);
        }
    }

    /* === Reconstruction walk === */
recon_phase:
    if(do_recon && found >= 0){
        printf("\n═══ RECONSTRUCTION ═══\n");
        printf("  walking %d steps, limit=%lld\n", fi, (long long)sol_limit);
        fflush(stdout);
        double walk_t0 = now_ms();

        SolWriter sw;
        solw_init(&sw, out_path, (u64)sol_limit);
        if (per_k_limit >= 0) sw.per_k_limit = (u64)per_k_limit;
        if (find_k_n > 0) {
            solw_set_find_k(&sw, find_k_arr, find_k_n, n);
            printf("  --find-k mode: requesting ks =");
            for (int i = 0; i < find_k_n; i++) printf(" %d", find_k_arr[i]);
            printf("  (per-k cap = %llu)\n", (unsigned long long)sw.per_k_limit);
        }
        if(!sw.fp){
            fprintf(stderr,"could not open output file %s\n", out_path);
        } else {
            Walker w;
            w.items = items;
            w.n = n;
            w.search_T = search_T;
            w.flipped = (search_T != T) ? 1 : 0;
            w.dir = run_dir;
            w.sw = &sw;
            w.taken_values = malloc(n * sizeof(i64));
            w.taken_depth = 0;
            w.nodes_visited = 0;
            w.nodes_forced_take = 0;
            w.nodes_forced_skip = 0;
            w.nodes_branching = 0;
            w.nodes_dead = 0;
            w.walk_start = walk_t0;
            w.seed_initialized = 0;
            /* Initialize the LRU cache. Default capacity = max(64, n).
             * For n=1000 frontiers averaging a few KB each, that's a few MB
             * of cache memory — fits comfortably. Override via --cache N. */
            FrontierCache fc;
            int cache_cap = (cache_capacity > 0) ? cache_capacity : (n > 64 ? n : 64);
            u64 cache_bytes = (cache_mb > 0) ? (u64)cache_mb * 1024ULL * 1024ULL : 0;
            /* If user gave --cache-mb but not --cache, drop the entry-count
             * hard cap so the byte budget is the only limiter. */
            if (cache_mb > 0 && cache_capacity == 0) cache_cap = 0;
            fc_init(&fc, fi, cache_cap, cache_bytes);
            if (cache_mb > 0) {
                printf("  cache: entry cap=%d, byte budget=%lld MB\n",
                    cache_cap, (long long)cache_mb);
            }
            w.cache = &fc;
            w.random_order = random_order;
            w.rng_state = (u64)seed * 2654435769ULL + 1;
            if (w.rng_state == 0) w.rng_state = 0xdeadbeefULL;
            /* Start at step fi-1 (last saved frontier) with target = search_T.
             * The saved frontier at index (fi-1) includes items[0..fi-1]. */
            walker_dfs(&w, fi - 1, search_T);
            free(w.taken_values);
            if (w.seed_initialized) frontier_free(&w.seed_front);

            double walk_ms = now_ms() - walk_t0;
            printf("  solutions found: %llu (limit=%lld)\n",
                (unsigned long long)sw.count, (long long)sol_limit);
            printf("  nodes visited:   %llu\n", (unsigned long long)w.nodes_visited);
            printf("    forced TAKE:   %llu (%.1f%%)\n",
                (unsigned long long)w.nodes_forced_take,
                w.nodes_visited?100.0*w.nodes_forced_take/w.nodes_visited:0);
            printf("    forced SKIP:   %llu (%.1f%%)\n",
                (unsigned long long)w.nodes_forced_skip,
                w.nodes_visited?100.0*w.nodes_forced_skip/w.nodes_visited:0);
            printf("    branching:     %llu (%.1f%%)\n",
                (unsigned long long)w.nodes_branching,
                w.nodes_visited?100.0*w.nodes_branching/w.nodes_visited:0);
            printf("    dead-end:      %llu (%.1f%%)\n",
                (unsigned long long)w.nodes_dead,
                w.nodes_visited?100.0*w.nodes_dead/w.nodes_visited:0);
            printf("  walk time:       %.0fms\n", walk_ms);
            u64 total_lookups = fc.hits + fc.misses;
            printf("  cache: %llu hits / %llu misses (%.1f%% hit rate), %llu evictions, peak resident=%llu/%d\n",
                (unsigned long long)fc.hits, (unsigned long long)fc.misses,
                total_lookups ? 100.0*fc.hits/total_lookups : 0,
                (unsigned long long)fc.evictions,
                (unsigned long long)fc.peak_resident, cache_cap);
            {
                char pb[32];
                printf("         peak cache bytes: %s\n", fmt_bytes(fc.peak_bytes, pb));
            }
            if (find_k_n > 0) {
                printf("\n  ── find-k results ──\n");
                for (int i = 0; i < find_k_n; i++) {
                    if (sw.find_k_found[i] > 0) {
                        printf("    k=%d: %llu solution%s found\n",
                            find_k_arr[i],
                            (unsigned long long)sw.find_k_found[i],
                            sw.find_k_found[i] == 1 ? "" : "s");
                    } else {
                        printf("    k=%d: NONE FOUND\n", find_k_arr[i]);
                    }
                }
            }
            solw_close(&sw);
            if(sw.count > 0){
                printf("  k range observed: %d..%d\n", sw.min_k_seen, sw.max_k_seen);
                printf("  sorting %s by k...\n", out_path);
                solw_sort_file(out_path);
                printf("  done. Output: %s\n", out_path);
            }
            fc_free(&fc);
        }

        /* Frontier files are intentionally preserved for later --recon-from */
    }

    free(fwd.rc_buf); free(items); return 0;
}