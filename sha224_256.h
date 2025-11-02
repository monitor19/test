/*
 * Copyright 2019-2024 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _XF_SECURITY_SHA224_256_HPP_
#define _XF_SECURITY_SHA224_256_HPP_

#include <ap_int.h>
#include <hls_stream.h>

// For debug
#ifndef __SYNTHESIS__
#include <cstdio>
#endif

#ifndef _DEBUG
#define _DEBUG (0)
#endif

#define _XF_SECURITY_VOID_CAST static_cast<void>
// XXX toggle here to debug this file
#define _XF_SECURITY_PRINT(msg...) \
    do {                           \
        if (_DEBUG) printf(msg);   \
    } while (0)

// SHA-256 宏定义
#define ROTR(n, x) ((x >> n) | (x << (32 - n)))
#define ROTL(n, x) ((x << n) | (x >> (32 - n)))
#define SHR(n, x) (x >> n)
#define CH(x, y, z) ((x & y) ^ ((~x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

namespace xf {
namespace security {
namespace internal {

/// Processing block
struct SHA256Block {
    uint32_t M[16];
};

/// @brief Static config for SHA224 and SHA256.
template <bool do_sha224>
struct sha256_digest_config;

template <>
struct sha256_digest_config<true> {
    static const short numH = 7;
};

template <>
struct sha256_digest_config<false> {
    static const short numH = 8;
};

/// @brief Generate 512bit processing blocks for SHA224/SHA256 (pipeline)
inline void preProcessing(hls::stream<ap_uint<32> >& msg_strm,
                          hls::stream<ap_uint<64> >& len_strm,
                          hls::stream<bool>& end_len_strm,
                          hls::stream<SHA256Block>& blk_strm,
                          hls::stream<uint64_t>& nblk_strm,
                          hls::stream<bool>& end_nblk_strm) {
LOOP_SHA256_GENENERATE_MAIN:
    for (bool end_flag = end_len_strm.read(); !end_flag; end_flag = end_len_strm.read()) {
        /// message length in byte.
        uint64_t len = len_strm.read();
        /// message length in bit.
        uint64_t L = 8 * len;
        /// total number blocks to digest.
        uint64_t blk_num = (len >> 6) + 1 + ((len & 0x3f) > 55);
        // inform digest function.
        nblk_strm.write(blk_num);
        end_nblk_strm.write(false);

    LOOP_SHA256_GEN_FULL_BLKS:
        for (uint64_t j = 0; j < uint64_t(len >> 6); ++j) {
#pragma HLS pipeline II = 16
#pragma HLS loop_tripcount min = 0 max = 1
            /// message block.
            SHA256Block b0;
#pragma HLS array_partition variable = b0.M complete
        // this block will hold 64 byte of message.
        LOOP_SHA256_GEN_ONE_FULL_BLK:
            for (int i = 0; i < 16; ++i) {
#pragma HLS unroll
                uint32_t l = msg_strm.read();
                // XXX algorithm assumes big-endian.
                l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                    ((0xff000000UL & l) >> 24);
                b0.M[i] = l;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32bx16)\n", i, b0.M[i]);
            }
            // send block
            blk_strm.write(b0);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        }

        /// number of bytes not in blocks yet.
        char left = (char)(len & 0x3fULL); // < 64

        _XF_SECURITY_PRINT("DEBUG: sent = %d, left = %d\n", int(len & (-1ULL ^ 0x3fULL)), (int)left);

        if (left == 0) {
            // end at block boundary, start with pad 1.
            /// last block
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete
            // pad 1
            b.M[0] = 0x80000000UL;
            _XF_SECURITY_PRINT("DEBUG: M[0] =\t%08x (pad 1)\n", b.M[0]);
        // zero
        LOOP_SHA256_GEN_PAD_13_ZEROS:
            for (int i = 1; i < 14; ++i) {
#pragma HLS unroll
                b.M[i] = 0;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b.M[i]);
            }
            // append L
            b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);
            // emit
            blk_strm.write(b);
        } else if (left < 56) {
            // can pad 1 and append L.
            // last message block.
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete

        LOOP_SHA256_GEN_COPY_TAIL_AND_ONE:
            for (int i = 0; i < 14; ++i) {
#pragma HLS pipeline
                if (i < (left >> 2)) {
                    uint32_t l = msg_strm.read();
                    // pad 1 byte not in this word
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32b)\n", i, b.M[i]);
                } else if (i > (left >> 2)) {
                    // pad 1 not in this word, and no word to read.
                    b.M[i] = 0UL;
                } else {
                    // pad 1 byte in this word
                    uint32_t e = left & 3L;
                    if (e == 0) {
                        b.M[i] = 0x80000000UL;
                    } else if (e == 1) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24);
                        b.M[i] = l | 0x00800000UL;
                    } else if (e == 2) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                        b.M[i] = l | 0x00008000UL;
                    } else {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                        b.M[i] = l | 0x00000080UL;
                    }
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i, b.M[i]);
                }
            }
            // append L
            b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);

            blk_strm.write(b);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        } else {
            // cannot append L.
            /// last but 1 block.
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete
        // copy and pad 1
        LOOP_SHA256_GEN_COPY_TAIL_ONLY:
            for (int i = 0; i < 16; ++i) {
#pragma HLS unroll
                if (i < (left >> 2)) {
                    // pad 1 byte not in this word
                    uint32_t l = msg_strm.read();
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32b)\n", i, b.M[i]);
                } else if (i > (left >> 2)) {
                    // pad 1 byte not in this word, and no msg word to read
                    b.M[i] = 0UL;
                } else {
                    // last in this word
                    uint32_t e = left & 3L;
                    if (e == 0) {
                        b.M[i] = 0x80000000UL;
                    } else if (e == 1) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24);
                        b.M[i] = l | 0x00800000UL;
                    } else if (e == 2) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                        b.M[i] = l | 0x00008000UL;
                    } else {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                        b.M[i] = l | 0x00000080UL;
                    }
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i, b.M[i]);
                }
            }
            blk_strm.write(b);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");

            /// last block.
            SHA256Block b1;
#pragma HLS array_partition variable = b1.M complete
        LOOP_SHA256_GEN_L_ONLY_BLK:
            for (int i = 0; i < 14; ++i) {
#pragma HLS unroll
                b1.M[i] = 0;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b1.M[i]);
            }
            // append L
            b1.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b1.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b1.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b1.M[15]);

            blk_strm.write(b1);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        }
    } // main loop
    end_nblk_strm.write(true);
} // preProcessing (32-bit ver)

inline void dup_strm(hls::stream<uint64_t>& in_strm,
                     hls::stream<bool>& in_e_strm,
                     hls::stream<uint64_t>& out1_strm,
                     hls::stream<bool>& out1_e_strm,
                     hls::stream<uint64_t>& out2_strm,
                     hls::stream<bool>& out2_e_strm) {
    bool e = in_e_strm.read();

    while (!e) {
#pragma HLS loop_tripcount min = 1 max = 1 avg = 1
#pragma HLS pipeline II = 1
        uint64_t in_r = in_strm.read();

        out1_strm.write(in_r);
        out1_e_strm.write(false);
        out2_strm.write(in_r);
        out2_e_strm.write(false);

        e = in_e_strm.read();
    }

    out1_e_strm.write(true);
    out2_e_strm.write(true);
}

/// @brief 优化的消息调度生成函数
inline void generateMsgSchedule_optimized(hls::stream<SHA256Block>& blk_strm,
                                         hls::stream<uint64_t>& nblk_strm,
                                         hls::stream<bool>& end_nblk_strm,
                                         hls::stream<uint32_t>& w_strm) {
    bool e = end_nblk_strm.read();
    
    while (!e) {
        uint64_t n = nblk_strm.read();
        
        for (uint64_t i = 0; i < n; ++i) {
#pragma HLS LATENCY max=48  // 优化：减少最大延迟
            
            SHA256Block blk = blk_strm.read();
#pragma HLS array_partition variable=blk.M complete

            // 优化：使用循环分区提高并行度
            uint32_t W[64];
#pragma HLS array_partition variable=W cyclic factor=4

            // 阶段1: 并行加载前16个W值
            for (short t = 0; t < 16; t += 4) {
#pragma HLS pipeline II=1
#pragma HLS unroll factor=4
                W[t] = blk.M[t];
                W[t+1] = blk.M[t+1]; 
                W[t+2] = blk.M[t+2];
                W[t+3] = blk.M[t+3];
                
                w_strm.write(W[t]);
                w_strm.write(W[t+1]);
                w_strm.write(W[t+2]); 
                w_strm.write(W[t+3]);
            }

            // 阶段2: 优化W[16:63]计算流水线
            for (short t = 16; t < 64; t += 2) {
#pragma HLS pipeline II=1
#pragma HLS dependence variable=W inter false
                
                // 并行计算两个W值
                uint32_t Wt1 = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
                uint32_t Wt2 = SSIG1(W[t-1]) + W[t-6] + SSIG0(W[t-14]) + W[t-15];
                
                W[t] = Wt1;
                W[t+1] = Wt2;
                
                w_strm.write(Wt1);
                w_strm.write(Wt2);
            }
        }
        e = end_nblk_strm.read();
    }
}

/// @brief 优化的SHA-256迭代函数
inline void sha256_iter_optimized(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                                 uint32_t& e, uint32_t& f, uint32_t& g, uint32_t& h,
                                 hls::stream<uint32_t>& w_strm,
                                 uint32_t& Kt, const uint32_t K[], short t) {
#pragma HLS INLINE
    uint32_t Wt = w_strm.read();
    
    // 预计算常用表达式减少关键路径
    uint32_t ch = CH(e, f, g);
    uint32_t maj = MAJ(a, b, c);
    uint32_t bsig0 = BSIG0(a);
    uint32_t bsig1 = BSIG1(e);
    
    // 并行计算T1和T2
    uint32_t T1, T2;
    T1 = h + bsig1 + ch + Kt + Wt;
    T2 = bsig0 + maj;

    // 更新工作变量 - 使用寄存器重命名减少依赖
    h = g;
    g = f; 
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;

    // 预取下一个Kt值
    Kt = K[(t + 1) & 63];

    _XF_SECURITY_PRINT(
        "DEBUG: Kt=%08x, Wt=%08x\n"
        "\ta=%08x, b=%08x, c=%08x, d=%08x\n"
        "\te=%08x, f=%08x, g=%08x, h=%08x\n",
        Kt, Wt, a, b, c, d, e, f, g, h);
}

/// @brief 优化的SHA-256摘要计算函数
template <int h_width>
void sha256Digest_optimized(hls::stream<uint64_t>& nblk_strm,
                           hls::stream<bool>& end_nblk_strm,
                           hls::stream<uint32_t>& w_strm,
                           hls::stream<ap_uint<h_width> >& hash_strm,
                           hls::stream<bool>& end_hash_strm) {
    
    /// constant K with cyclic partitioning for better parallel access
    static const uint32_t K[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};
#pragma HLS array_partition variable=K cyclic factor=4

LOOP_SHA256_DIGEST_MAIN_OPT:
    for (bool end_flag = end_nblk_strm.read(); !end_flag; end_flag = end_nblk_strm.read()) {
        uint64_t blk_num = nblk_strm.read();

        /// internal states with complete partitioning
        uint32_t H[8];
#pragma HLS array_partition variable=H complete

        // initialize H values
        if (h_width == 224) {
            H[0] = 0xc1059ed8UL; H[1] = 0x367cd507UL; H[2] = 0x3070dd17UL; H[3] = 0xf70e5939UL;
            H[4] = 0xffc00b31UL; H[5] = 0x68581511UL; H[6] = 0x64f98fa7UL; H[7] = 0xbefa4fa4UL;
        } else {
            H[0] = 0x6a09e667UL; H[1] = 0xbb67ae85UL; H[2] = 0x3c6ef372UL; H[3] = 0xa54ff53aUL;
            H[4] = 0x510e527fUL; H[5] = 0x9b05688cUL; H[6] = 0x1f83d9abUL; H[7] = 0x5be0cd19UL;
        }

    LOOP_SHA256_DIGEST_NBLK_OPT:
        for (uint64_t n = 0; n < blk_num; ++n) {
#pragma HLS pipeline II=1  // 关键优化：每个时钟周期处理一个块
            
            uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint32_t e_val = H[4], f = H[5], g = H[6], h_val = H[7];
            
            uint32_t Kt = K[0];

            // 64轮计算，完全流水线化
        LOOP_SHA256_64_ROUNDS_OPT:
            for (short t = 0; t < 64; ++t) {
#pragma HLS pipeline II=1
                sha256_iter_optimized(a, b, c, d, e_val, f, g, h_val, w_strm, Kt, K, t);
            }

            // 更新内部状态
            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e_val; H[5] += f; H[6] += g; H[7] += h_val;
        }

        // 输出哈希值
        ap_uint<h_width> hash_val;
        const short numH = (h_width == 224) ? 7 : 8;
        
    LOOP_OUTPUT_HASH_OPT:
        for (short i = 0; i < numH; ++i) {
#pragma HLS unroll
            uint32_t l = H[i];
            // 大端序转小端序
            uint32_t l_little = ((l >> 24) & 0xff) | 
                               (((l >> 16) & 0xff) << 8) | 
                               (((l >> 8) & 0xff) << 16) | 
                               ((l & 0xff) << 24);
            hash_val.range(32*i + 31, 32*i) = l_little;
        }
        
        hash_strm.write(hash_val);
        end_hash_strm.write(false);
    }
    
    end_hash_strm.write(true);
}

// 原始函数保持兼容性
inline void generateMsgSchedule(hls::stream<SHA256Block>& blk_strm,
                                hls::stream<uint64_t>& nblk_strm,
                                hls::stream<bool>& end_nblk_strm,
                                hls::stream<uint32_t>& w_strm) {
    bool e = end_nblk_strm.read();
    while (!e) {
        uint64_t n = nblk_strm.read();
        for (uint64_t i = 0; i < n; ++i) {
#pragma HLS latency max = 65

            SHA256Block blk = blk_strm.read();
#pragma HLS array_partition variable = blk.M complete

            uint32_t W[16];
#pragma HLS array_partition variable = W complete

        LOOP_SHA256_PREPARE_WT16:
            for (short t = 0; t < 16; ++t) {
#pragma HLS pipeline II = 1
                uint32_t Wt = blk.M[t];
                W[t] = Wt;
                w_strm.write(Wt);
            }

        LOOP_SHA256_PREPARE_WT64:
            for (short t = 16; t < 64; ++t) {
#pragma HLS pipeline II = 1
                uint32_t Wt = SSIG1(W[14]) + W[9] + SSIG0(W[1]) + W[0];
                for (unsigned char j = 0; j < 15; ++j) {
                    W[j] = W[j + 1];
                }
                W[15] = Wt;
                w_strm.write(Wt);
            }
        }
        e = end_nblk_strm.read();
    }
}

// 原始迭代函数保持兼容性
inline void sha256_iter(uint32_t& a,
                        uint32_t& b,
                        uint32_t& c,
                        uint32_t& d,
                        uint32_t& e,
                        uint32_t& f,
                        uint32_t& g,
                        uint32_t& h,
                        hls::stream<uint32_t>& w_strm,
                        uint32_t& Kt,
                        const uint32_t K[],
                        short t) {
    uint32_t Wt = w_strm.read();
    uint32_t T1, T2;
    T1 = h + BSIG1(e) + CH(e, f, g) + Kt + Wt;
    T2 = BSIG0(a) + MAJ(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;

    _XF_SECURITY_PRINT(
        "DEBUG: Kt=%08x, Wt=%08x\n"
        "\ta=%08x, b=%08x, c=%08x, d=%08x\n"
        "\te=%08x, f=%08x, g=%08x, h=%08x\n",
        Kt, Wt, a, b, c, d, e, f, g, h);

    Kt = K[(t + 1) & 63];
}

// 原始摘要函数保持兼容性
template <int h_width>
void sha256Digest(hls::stream<uint64_t>& nblk_strm,
                  hls::stream<bool>& end_nblk_strm,
                  hls::stream<uint32_t>& w_strm,
                  hls::stream<ap_uint<h_width> >& hash_strm,
                  hls::stream<bool>& end_hash_strm) {
    static const uint32_t K[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};
#pragma HLS array_partition variable = K complete

LOOP_SHA256_DIGEST_MAIN:
    for (bool end_flag = end_nblk_strm.read(); !end_flag; end_flag = end_nblk_strm.read()) {
        uint64_t blk_num = nblk_strm.read();

        uint32_t H[8];
#pragma HLS array_partition variable = H complete

        if (h_width == 224) {
            H[0] = 0xc1059ed8UL; H[1] = 0x367cd507UL; H[2] = 0x3070dd17UL; H[3] = 0xf70e5939UL;
            H[4] = 0xffc00b31UL; H[5] = 0x68581511UL; H[6] = 0x64f98fa7UL; H[7] = 0xbefa4fa4UL;
        } else {
            H[0] = 0x6a09e667UL; H[1] = 0xbb67ae85UL; H[2] = 0x3c6ef372UL; H[3] = 0xa54ff53aUL;
            H[4] = 0x510e527fUL; H[5] = 0x9b05688cUL; H[6] = 0x1f83d9abUL; H[7] = 0x5be0cd19UL;
        }

    LOOP_SHA256_DIGEST_NBLK:
        for (uint64_t n = 0; n < blk_num; ++n) {
#pragma HLS loop_tripcount min = 1 max = 1
#pragma HLS latency max = 65

            uint32_t a, b, c, d, e_val, f, g, h_val;
            a = H[0]; b = H[1]; c = H[2]; d = H[3];
            e_val = H[4]; f = H[5]; g = H[6]; h_val = H[7];

            uint32_t Kt = K[0];
        LOOP_SHA256_UPDATE_64_ROUNDS:
            for (short t = 0; t < 64; ++t) {
#pragma HLS pipeline II = 1
                sha256_iter(a, b, c, d, e_val, f, g, h_val, w_strm, Kt, K, t);
            }

            H[0] = a + H[0]; H[1] = b + H[1]; H[2] = c + H[2]; H[3] = d + H[3];
            H[4] = e_val + H[4]; H[5] = f + H[5]; H[6] = g + H[6]; H[7] = h_val + H[7];
        }

        if (h_width == 224) {
            ap_uint<224> w224;
        LOOP_SHA256_EMIT_H224:
            for (short i = 0; i < sha256_digest_config<true>::numH; ++i) {
#pragma HLS unroll
                uint32_t l = H[i];
                uint8_t t0 = (((l) >> 24) & 0xff);
                uint8_t t1 = (((l) >> 16) & 0xff);
                uint8_t t2 = (((l) >> 8) & 0xff);
                uint8_t t3 = (((l)) & 0xff);
                uint32_t l_little = ((uint32_t)t0) | (((uint32_t)t1) << 8) | (((uint32_t)t2) << 16) | (((uint32_t)t3) << 24);
                w224.range(32 * i + 31, 32 * i) = l_little;
            }
            hash_strm.write(w224);
        } else {
            ap_uint<256> w256;
        LOOP_SHA256_EMIT_H256:
            for (short i = 0; i < sha256_digest_config<false>::numH; ++i) {
#pragma HLS unroll
                uint32_t l = H[i];
                uint8_t t0 = (((l) >> 24) & 0xff);
                uint8_t t1 = (((l) >> 16) & 0xff);
                uint8_t t2 = (((l) >> 8) & 0xff);
                uint8_t t3 = (((l)) & 0xff);
                uint32_t l_little = ((uint32_t)t0) | (((uint32_t)t1) << 8) | (((uint32_t)t2) << 16) | (((uint32_t)t3) << 24);
                w256.range(32 * i + 31, 32 * i) = l_little;
            }
            hash_strm.write(w256);
        }
        end_hash_strm.write(false);
    }
    end_hash_strm.write(true);
}

/// @brief 优化的SHA-256顶层函数
template <int m_width, int h_width>
void sha256_top_optimized(hls::stream<ap_uint<m_width> >& msg_strm,
                         hls::stream<ap_uint<64> >& len_strm,
                         hls::stream<bool>& end_len_strm,
                         hls::stream<ap_uint<h_width> >& hash_strm,
                         hls::stream<bool>& end_hash_strm) {
#pragma HLS dataflow
    
    hls::stream<SHA256Block> blk_strm;
#pragma HLS stream variable = blk_strm depth = 32
    hls::stream<uint64_t> nblk_strm;
#pragma HLS stream variable = nblk_strm depth = 32
    hls::stream<bool> end_nblk_strm;
#pragma HLS stream variable = end_nblk_strm depth = 32
    hls::stream<uint64_t> nblk_strm1;
#pragma HLS stream variable = nblk_strm1 depth = 32
    hls::stream<bool> end_nblk_strm1;
#pragma HLS stream variable = end_nblk_strm1 depth = 32
    hls::stream<uint64_t> nblk_strm2;
#pragma HLS stream variable = nblk_strm2 depth = 32
    hls::stream<bool> end_nblk_strm2;
#pragma HLS stream variable = end_nblk_strm2 depth = 32
    hls::stream<uint32_t> w_strm;
#pragma HLS stream variable = w_strm depth = 64  // 增加深度以支持更好的流水线

    // 使用优化的数据流
    preProcessing(msg_strm, len_strm, end_len_strm, blk_strm, nblk_strm, end_nblk_strm);
    dup_strm(nblk_strm, end_nblk_strm, nblk_strm1, end_nblk_strm1, nblk_strm2, end_nblk_strm2);
    generateMsgSchedule_optimized(blk_strm, nblk_strm1, end_nblk_strm1, w_strm);
    sha256Digest_optimized<h_width>(nblk_strm2, end_nblk_strm2, w_strm, hash_strm, end_hash_strm);
}

/// @brief 原始SHA-256顶层函数保持兼容性
template <int m_width, int h_width>
void sha256_top(hls::stream<ap_uint<m_width> >& msg_strm,
                hls::stream<ap_uint<64> >& len_strm,
                hls::stream<bool>& end_len_strm,
                hls::stream<ap_uint<h_width> >& hash_strm,
                hls::stream<bool>& end_hash_strm) {
#pragma HLS dataflow
    hls::stream<SHA256Block> blk_strm;
#pragma HLS stream variable = blk_strm depth = 32
    hls::stream<uint64_t> nblk_strm;
#pragma HLS stream variable = nblk_strm depth = 32
    hls::stream<bool> end_nblk_strm;
#pragma HLS stream variable = end_nblk_strm depth = 32
    hls::stream<uint64_t> nblk_strm1;
#pragma HLS stream variable = nblk_strm1 depth = 32
    hls::stream<bool> end_nblk_strm1;
#pragma HLS stream variable = end_nblk_strm1 depth = 32
    hls::stream<uint64_t> nblk_strm2;
#pragma HLS stream variable = nblk_strm2 depth = 32
    hls::stream<bool> end_nblk_strm2;
#pragma HLS stream variable = end_nblk_strm2 depth = 32
    hls::stream<uint32_t> w_strm;
#pragma HLS stream variable = w_strm depth = 32

    preProcessing(msg_strm, len_strm, end_len_strm, blk_strm, nblk_strm, end_nblk_strm);
    dup_strm(nblk_strm, end_nblk_strm, nblk_strm1, end_nblk_strm1, nblk_strm2, end_nblk_strm2);
    generateMsgSchedule(blk_strm, nblk_strm1, end_nblk_strm1, w_strm);
    sha256Digest(nblk_strm2, end_nblk_strm2, w_strm, hash_strm, end_hash_strm);
}

} // namespace internal

/// @brief 优化的SHA-224算法
template <int m_width>
void sha224_optimized(hls::stream<ap_uint<m_width> >& msg_strm,
                     hls::stream<ap_uint<64> >& len_strm,
                     hls::stream<bool>& end_len_strm,
                     hls::stream<ap_uint<224> >& hash_strm,
                     hls::stream<bool>& end_hash_strm) {
    internal::sha256_top_optimized<m_width, 224>(msg_strm, len_strm, end_len_strm, hash_strm, end_hash_strm);
}

/// @brief 优化的SHA-256算法
template <int m_width>
void sha256_optimized(hls::stream<ap_uint<m_width> >& msg_strm,
                     hls::stream<ap_uint<64> >& len_strm,
                     hls::stream<bool>& end_len_strm,
                     hls::stream<ap_uint<256> >& hash_strm,
                     hls::stream<bool>& end_hash_strm) {
    internal::sha256_top_optimized<m_width, 256>(msg_strm, len_strm, end_len_strm, hash_strm, end_hash_strm);
}

/// @brief 原始SHA-224算法保持兼容性
template <int m_width>
void sha224(hls::stream<ap_uint<m_width> >& msg_strm,
            hls::stream<ap_uint<64> >& len_strm,
            hls::stream<bool>& end_len_strm,
            hls::stream<ap_uint<224> >& hash_strm,
            hls::stream<bool>& end_hash_strm) {
    internal::sha256_top(msg_strm, len_strm, end_len_strm, hash_strm, end_hash_strm);
}

/// @brief 原始SHA-256算法保持兼容性
template <int m_width>
void sha256(hls::stream<ap_uint<m_width> >& msg_strm,
            hls::stream<ap_uint<64> >& len_strm,
            hls::stream<bool>& end_len_strm,
            hls::stream<ap_uint<256> >& hash_strm,
            hls::stream<bool>& end_hash_strm) {
    internal::sha256_top(msg_strm, len_strm, end_len_strm, hash_strm, end_hash_strm);
}

} // namespace security
} // namespace xf

// Clean up macros.
#undef ROTR
#undef ROTL
#undef SHR
#undef CH
#undef MAJ
#undef BSIG0
#undef BSIG1
#undef SSIG0
#undef SSIG1

#undef _XF_SECURITY_PRINT
#undef _XF_SECURITY_VOID_CAST

#endif // _XF_SECURITY_SHA224_256_HPP_
