##############################################################################
#  Makefile – constant-time proof for OpenSSL’s TLS handshake with SMACK
#
#  Requirements:
#    * clang/llvm + wllvm + extract-bc  (for bit-code generation)
#    * SMACK 2.8+                       (smack, llvm-link, opt)
#    * OpenSSL headers in ../include    (adjust INC if different)
##############################################################################

# ---------------------------------------------------------------------------
# 1.  Configuration – adjust paths / flags if needed
# ---------------------------------------------------------------------------
SMACK_FLAGS  := --pthread --verifier boogie --no-verify
CC           := clang
LLVM_LINK    := llvm-link
OPT          := opt
SMACK        := smack

# ---------------------------------------------------------------------------
# 2.  Source lists
# ---------------------------------------------------------------------------
# ----------------------------------------------------------------------
#  Core libssl sources required for the TLS/DTLS handshake
# ----------------------------------------------------------------------
LIBSSL_SRC := \
    ssl/bio_ssl.c \
    ssl/d1_lib.c \
    ssl/d1_msg.c \
    ssl/d1_srtp.c \
    ssl/methods.c \
    ssl/pqueue.c \
    ssl/s3_enc.c \
    ssl/s3_lib.c \
    ssl/s3_msg.c \
    ssl/ssl_asn1.c \
    ssl/ssl_cert.c \
    ssl/ssl_cert_comp.c \
    ssl/ssl_ciph.c \
    ssl/ssl_conf.c \
    ssl/ssl_err_legacy.c \
    ssl/ssl_init.c \
    ssl/ssl_lib.c \
    ssl/ssl_mcnf.c \
    ssl/ssl_rsa.c \
    ssl/ssl_rsa_legacy.c \
    ssl/ssl_sess.c \
    ssl/ssl_stat.c \
    ssl/ssl_txt.c \
    ssl/ssl_utst.c \
    ssl/t1_enc.c \
    ssl/t1_lib.c \
    ssl/t1_trce.c \
    ssl/tls13_enc.c \
    ssl/tls_depr.c \
    ssl/tls_srp.c \
    ssl/quic/quic_tls.c \
    ssl/quic/quic_tls_api.c \
    ssl/record/rec_layer_d1.c \
    ssl/record/rec_layer_s3.c \
    ssl/record/methods/dtls_meth.c \
    ssl/record/methods/ssl3_meth.c \
    ssl/record/methods/tls13_meth.c \
    ssl/record/methods/tls1_meth.c \
    ssl/record/methods/tls_common.c \
    ssl/record/methods/tls_multib.c \
    ssl/record/methods/tlsany_meth.c \
    ssl/rio/poll_immediate.c \
    ssl/statem/extensions.c \
    ssl/statem/extensions_clnt.c \
    ssl/statem/extensions_cust.c \
    ssl/statem/extensions_srvr.c \
    ssl/statem/statem.c \
    ssl/statem/statem_clnt.c \
    ssl/statem/statem_dtls.c \
    ssl/statem/statem_lib.c \
    ssl/statem/statem_srvr.c

BIO_SRC := \
    crypto/bio/bio_lib.c crypto/bio/bio_cb.c crypto/bio/bio_err.c \
    crypto/bio/bio_print.c crypto/bio/bio_dump.c crypto/bio/bio_addr.c \
    crypto/bio/bio_sock.c crypto/bio/bio_sock2.c crypto/bio/bio_meth.c \
    crypto/bio/ossl_core_bio.c \
    crypto/bio/bss_null.c crypto/bio/bss_mem.c crypto/bio/bss_bio.c \
    crypto/bio/bss_fd.c crypto/bio/bss_file.c crypto/bio/bss_sock.c \
    crypto/bio/bss_conn.c crypto/bio/bss_acpt.c crypto/bio/bss_dgram.c \
    crypto/bio/bss_log.c crypto/bio/bss_core.c crypto/bio/bss_dgram_pair.c \
    crypto/bio/bf_null.c crypto/bio/bf_buff.c crypto/bio/bf_lbuf.c \
    crypto/bio/bf_nbio.c crypto/bio/bf_prefix.c crypto/bio/bf_readbuff.c

AES_SRC := \
    crypto/aes/aes_core.c \
    crypto/aes/aes_cbc.c \
    crypto/aes/aes_misc.c \
    crypto/aes/aes_ecb.c \
    crypto/aes/aes_cfb.c \
    crypto/aes/aes_ofb.c \
    crypto/aes/aes_wrap.c

OPENSSL_ASN1_SRC := \
  crypto/asn1/a_bitstr.c \
  crypto/asn1/a_d2i_fp.c \
  crypto/asn1/a_digest.c \
  crypto/asn1/a_dup.c \
  crypto/asn1/a_gentm.c \
  crypto/asn1/a_i2d_fp.c \
  crypto/asn1/a_int.c \
  crypto/asn1/a_mbstr.c \
  crypto/asn1/a_object.c \
  crypto/asn1/a_octet.c \
  crypto/asn1/a_print.c \
  crypto/asn1/a_sign.c \
  crypto/asn1/a_strex.c \
  crypto/asn1/a_strnid.c \
  crypto/asn1/a_time.c \
  crypto/asn1/a_type.c \
  crypto/asn1/a_utctm.c \
  crypto/asn1/a_utf8.c \
  crypto/asn1/a_verify.c \
  crypto/asn1/ameth_lib.c \
  crypto/asn1/asn1_err.c \
  crypto/asn1/asn1_gen.c \
  crypto/asn1/asn1_item_list.c \
  crypto/asn1/asn1_lib.c \
  crypto/asn1/asn1_parse.c \
  crypto/asn1/asn_mime.c \
  crypto/asn1/asn_moid.c \
  crypto/asn1/asn_mstbl.c \
  crypto/asn1/asn_pack.c \
  crypto/asn1/bio_asn1.c \
  crypto/asn1/bio_ndef.c \
  crypto/asn1/d2i_param.c \
  crypto/asn1/d2i_pr.c \
  crypto/asn1/d2i_pu.c \
  crypto/asn1/evp_asn1.c \
  crypto/asn1/f_int.c \
  crypto/asn1/f_string.c \
  crypto/asn1/i2d_evp.c \
  crypto/asn1/nsseq.c \
  crypto/asn1/p5_pbe.c \
  crypto/asn1/p5_pbev2.c \
  crypto/asn1/p5_scrypt.c \
  crypto/asn1/p8_pkey.c \
  crypto/asn1/t_bitst.c \
  crypto/asn1/t_pkey.c \
  crypto/asn1/t_spki.c \
  crypto/asn1/tasn_dec.c \
  crypto/asn1/tasn_enc.c \
  crypto/asn1/tasn_fre.c \
  crypto/asn1/tasn_new.c \
  crypto/asn1/tasn_prn.c \
  crypto/asn1/tasn_scn.c \
  crypto/asn1/tasn_typ.c \
  crypto/asn1/tasn_utl.c \
  crypto/asn1/x_algor.c \
  crypto/asn1/x_bignum.c \
  crypto/asn1/x_info.c \
  crypto/asn1/x_int64.c \
  crypto/asn1/x_long.c \
  crypto/asn1/x_pkey.c \
  crypto/asn1/x_sig.c \
  crypto/asn1/x_spki.c \
  crypto/asn1/x_val.c

OPENSSL_ASYNC_SRC := \
  crypto/async/arch/async_null.c   \
  crypto/async/arch/async_posix.c  \
  crypto/async/arch/async_win.c    \
  crypto/async/async.c             \
  crypto/async/async_err.c         \
  crypto/async/async_wait.c

# ──────────────────────────────────────────
#  X.509 and certificate-processing sources
# ──────────────────────────────────────────
X509_SRC := \
  crypto/x509/by_dir.c            \
  crypto/x509/by_file.c           \
  crypto/x509/by_store.c          \
  crypto/x509/pcy_cache.c         \
  crypto/x509/pcy_data.c          \
  crypto/x509/pcy_lib.c           \
  crypto/x509/pcy_map.c           \
  crypto/x509/pcy_node.c          \
  crypto/x509/pcy_tree.c          \
  crypto/x509/t_acert.c           \
  crypto/x509/t_crl.c             \
  crypto/x509/t_req.c             \
  crypto/x509/t_x509.c            \
  crypto/x509/v3_aaa.c            \
  crypto/x509/v3_ac_tgt.c         \
  crypto/x509/v3_addr.c           \
  crypto/x509/v3_admis.c          \
  crypto/x509/v3_akeya.c          \
  crypto/x509/v3_akid.c           \
  crypto/x509/v3_asid.c           \
  crypto/x509/v3_attrdesc.c       \
  crypto/x509/v3_attrmap.c        \
  crypto/x509/v3_audit_id.c       \
  crypto/x509/v3_authattid.c      \
  crypto/x509/v3_battcons.c       \
  crypto/x509/v3_bcons.c          \
  crypto/x509/v3_bitst.c          \
  crypto/x509/v3_conf.c           \
  crypto/x509/v3_cpols.c          \
  crypto/x509/v3_crld.c           \
  crypto/x509/v3_enum.c           \
  crypto/x509/v3_extku.c          \
  crypto/x509/v3_genn.c           \
  crypto/x509/v3_group_ac.c       \
  crypto/x509/v3_ia5.c            \
  crypto/x509/v3_ind_iss.c        \
  crypto/x509/v3_info.c           \
  crypto/x509/v3_int.c            \
  crypto/x509/v3_iobo.c           \
  crypto/x509/v3_ist.c            \
  crypto/x509/v3_lib.c            \
  crypto/x509/v3_ncons.c          \
  crypto/x509/v3_no_ass.c         \
  crypto/x509/v3_no_rev_avail.c   \
  crypto/x509/v3_pci.c            \
  crypto/x509/v3_pcia.c           \
  crypto/x509/v3_pcons.c          \
  crypto/x509/v3_pku.c            \
  crypto/x509/v3_pmaps.c          \
  crypto/x509/v3_prn.c            \
  crypto/x509/v3_purp.c           \
  crypto/x509/v3_rolespec.c       \
  crypto/x509/v3_san.c            \
  crypto/x509/v3_sda.c            \
  crypto/x509/v3_single_use.c     \
  crypto/x509/v3_skid.c           \
  crypto/x509/v3_soa_id.c         \
  crypto/x509/v3_sxnet.c          \
  crypto/x509/v3_timespec.c       \
  crypto/x509/v3_tlsf.c           \
  crypto/x509/v3_usernotice.c     \
  crypto/x509/v3_utf8.c           \
  crypto/x509/v3_utl.c            \
  crypto/x509/v3err.c             \
  crypto/x509/x509_acert.c        \
  crypto/x509/x509_att.c          \
  crypto/x509/x509_cmp.c          \
  crypto/x509/x509_d2.c           \
  crypto/x509/x509_def.c          \
  crypto/x509/x509_err.c          \
  crypto/x509/x509_ext.c          \
  crypto/x509/x509_lu.c           \
  crypto/x509/x509_meth.c         \
  crypto/x509/x509_obj.c          \
  crypto/x509/x509_r2x.c          \
  crypto/x509/x509_req.c          \
  crypto/x509/x509_set.c          \
  crypto/x509/x509_trust.c        \
  crypto/x509/x509_txt.c          \
  crypto/x509/x509_v3.c           \
  crypto/x509/x509_vfy.c          \
  crypto/x509/x509_vpm.c          \
  crypto/x509/x509aset.c          \
  crypto/x509/x509cset.c          \
  crypto/x509/x509name.c          \
  crypto/x509/x509rset.c          \
  crypto/x509/x509spki.c          \
  crypto/x509/x509type.c          \
  crypto/x509/x_all.c             \
  crypto/x509/x_attrib.c          \
  crypto/x509/x_crl.c             \
  crypto/x509/x_exten.c           \
  crypto/x509/x_ietfatt.c         \
  crypto/x509/x_name.c            \
  crypto/x509/x_pubkey.c          \
  crypto/x509/x_req.c             \
  crypto/x509/x_x509.c            \
  crypto/x509/x_x509a.c

# ───────────────────────────────
#  RAND, RSA, SEED, SHA, SLH-DSA
# ───────────────────────────────

# --- RAND (DRBG / legacy RAND code) ------------------------------
RAND_SRC := \
    crypto/rand/prov_seed.c          \
    crypto/rand/rand_deprecated.c    \
    crypto/rand/rand_err.c           \
    crypto/rand/rand_lib.c           \
    crypto/rand/rand_meth.c          \
    crypto/rand/rand_pool.c          \
    crypto/rand/rand_uniform.c       \
    crypto/rand/randfile.c

# --- RSA ----------------------------------------------------------
RSA_SRC := \
    crypto/rsa/rsa_ameth.c                  \
    crypto/rsa/rsa_asn1.c                   \
    crypto/rsa/rsa_backend.c                \
    crypto/rsa/rsa_chk.c                    \
    crypto/rsa/rsa_crpt.c                   \
    crypto/rsa/rsa_depr.c                   \
    crypto/rsa/rsa_err.c                    \
    crypto/rsa/rsa_gen.c                    \
    crypto/rsa/rsa_lib.c                    \
    crypto/rsa/rsa_meth.c                   \
    crypto/rsa/rsa_mp.c                     \
    crypto/rsa/rsa_mp_names.c               \
    crypto/rsa/rsa_none.c                   \
    crypto/rsa/rsa_oaep.c                   \
    crypto/rsa/rsa_ossl.c                   \
    crypto/rsa/rsa_pk1.c                    \
    crypto/rsa/rsa_pmeth.c                  \
    crypto/rsa/rsa_prn.c                    \
    crypto/rsa/rsa_pss.c                    \
    crypto/rsa/rsa_saos.c                   \
    crypto/rsa/rsa_schemes.c                \
    crypto/rsa/rsa_sign.c                   \
    crypto/rsa/rsa_sp800_56b_check.c        \
    crypto/rsa/rsa_sp800_56b_gen.c          \
    crypto/rsa/rsa_x931.c                   \
    crypto/rsa/rsa_x931g.c

# --- SEED block-cipher -------------------------------------------
SEED_SRC := \
    crypto/seed/seed.c      \
    crypto/seed/seed_cbc.c  \
    crypto/seed/seed_cfb.c  \
    crypto/seed/seed_ecb.c  \
    crypto/seed/seed_ofb.c

# --- SHA family --------------------------------------------------
SHA_SRC := \
    crypto/sha/keccak1600.c \
    crypto/sha/sha1_one.c   \
    crypto/sha/sha1dgst.c   \
    crypto/sha/sha256.c     \
    crypto/sha/sha3.c       \
    crypto/sha/sha512.c

# --- SLH-DSA (sphincs-like hash-based signatures) ----------------
SLH_DSA_SRC := \
    crypto/slh_dsa/slh_adrs.c      \
    crypto/slh_dsa/slh_dsa.c       \
    crypto/slh_dsa/slh_dsa_hash_ctx.c \
    crypto/slh_dsa/slh_dsa_key.c   \
    crypto/slh_dsa/slh_fors.c      \
    crypto/slh_dsa/slh_hash.c      \
    crypto/slh_dsa/slh_hypertree.c \
    crypto/slh_dsa/slh_params.c    \
    crypto/slh_dsa/slh_wots.c      \
    crypto/slh_dsa/slh_xmss.c

# ───────────────────────────────
#  Big-Number (BN) core
# ───────────────────────────────
BN_SRC := \
    crypto/bn/bn_add.c             \
    crypto/bn/bn_asm.c             \
    crypto/bn/bn_blind.c           \
    crypto/bn/bn_const.c           \
    crypto/bn/bn_conv.c            \
    crypto/bn/bn_ctx.c             \
    crypto/bn/bn_depr.c            \
    crypto/bn/bn_dh.c              \
    crypto/bn/bn_div.c             \
    crypto/bn/bn_err.c             \
    crypto/bn/bn_exp.c             \
    crypto/bn/bn_exp2.c            \
    crypto/bn/bn_gcd.c             \
    crypto/bn/bn_gf2m.c            \
    crypto/bn/bn_intern.c          \
    crypto/bn/bn_kron.c            \
    crypto/bn/bn_lib.c             \
    crypto/bn/bn_mod.c             \
    crypto/bn/bn_mont.c            \
    crypto/bn/bn_mpi.c             \
    crypto/bn/bn_mul.c             \
    crypto/bn/bn_nist.c            \
    crypto/bn/bn_prime.c           \
    crypto/bn/bn_print.c           \
    crypto/bn/bn_rand.c            \
    crypto/bn/bn_recp.c            \
    crypto/bn/bn_rsa_fips186_4.c   \
    crypto/bn/bn_shift.c           \
    crypto/bn/bn_sqr.c             \
    crypto/bn/bn_sqrt.c            \
    crypto/bn/bn_srp.c             \
    crypto/bn/bn_word.c            \
    crypto/bn/bn_x931p.c

# ───────────────────────────────
# 1.  ERROR–subsystem
# ───────────────────────────────
ERR_SRC := \
    crypto/err/err.c              \
    crypto/err/err_all.c          \
    crypto/err/err_all_legacy.c   \
    crypto/err/err_blocks.c       \
    crypto/err/err_mark.c         \
    crypto/err/err_prn.c          \
    crypto/err/err_save.c

# ───────────────────────────────
# 2.  ESS  (RFC-2634 Email Signing)
# ───────────────────────────────
ESS_SRC := \
    crypto/ess/ess_asn1.c         \
    crypto/ess/ess_err.c          \
    crypto/ess/ess_lib.c

# ───────────────────────────────
# 3.  EVP  (high-level crypto APIs)
# ───────────────────────────────
EVP_SRC := \
    crypto/evp/asymcipher.c                    \
    crypto/evp/bio_b64.c                       \
    crypto/evp/bio_enc.c                       \
    crypto/evp/bio_md.c                        \
    crypto/evp/bio_ok.c                        \
    crypto/evp/c_allc.c                        \
    crypto/evp/c_alld.c                        \
    crypto/evp/cmeth_lib.c                     \
    crypto/evp/ctrl_params_translate.c         \
    crypto/evp/dh_ctrl.c                       \
    crypto/evp/dh_support.c                    \
    crypto/evp/digest.c                        \
    crypto/evp/dsa_ctrl.c                      \
    crypto/evp/e_aes.c                         \
    crypto/evp/e_aes_cbc_hmac_sha1.c           \
    crypto/evp/e_aes_cbc_hmac_sha256.c         \
    crypto/evp/e_aria.c                        \
    crypto/evp/e_bf.c                          \
    crypto/evp/e_camellia.c                    \
    crypto/evp/e_cast.c                        \
    crypto/evp/e_chacha20_poly1305.c           \
    crypto/evp/e_des.c                         \
    crypto/evp/e_des3.c                        \
    crypto/evp/e_idea.c                        \
    crypto/evp/e_null.c                        \
    crypto/evp/e_old.c                         \
    crypto/evp/e_rc2.c                         \
    crypto/evp/e_rc4.c                         \
    crypto/evp/e_rc4_hmac_md5.c                \
    crypto/evp/e_rc5.c                         \
    crypto/evp/e_seed.c                        \
    crypto/evp/e_sm4.c                         \
    crypto/evp/e_xcbc_d.c                      \
    crypto/evp/ec_ctrl.c                       \
    crypto/evp/ec_support.c                    \
    crypto/evp/encode.c                        \
    crypto/evp/evp_cnf.c                       \
    crypto/evp/evp_enc.c                       \
    crypto/evp/evp_err.c                       \
    crypto/evp/evp_fetch.c                     \
    crypto/evp/evp_key.c                       \
    crypto/evp/evp_lib.c                       \
    crypto/evp/evp_pbe.c                       \
    crypto/evp/evp_pkey.c                      \
    crypto/evp/evp_rand.c                      \
    crypto/evp/evp_utils.c                     \
    crypto/evp/exchange.c                      \
    crypto/evp/kdf_lib.c                       \
    crypto/evp/kdf_meth.c                      \
    crypto/evp/kem.c                           \
    crypto/evp/keymgmt_lib.c                   \
    crypto/evp/keymgmt_meth.c                  \
    crypto/evp/legacy_md5.c                    \
    crypto/evp/legacy_md5_sha1.c               \
    crypto/evp/legacy_sha.c                    \
    crypto/evp/m_null.c                        \
    crypto/evp/m_sigver.c                      \
    crypto/evp/mac_lib.c                       \
    crypto/evp/mac_meth.c                      \
    crypto/evp/names.c                         \
    crypto/evp/p5_crpt.c                       \
    crypto/evp/p5_crpt2.c                      \
    crypto/evp/p_dec.c                         \
    crypto/evp/p_enc.c                         \
    crypto/evp/p_legacy.c                      \
    crypto/evp/p_lib.c                         \
    crypto/evp/p_open.c                        \
    crypto/evp/p_seal.c                        \
    crypto/evp/p_sign.c                        \
    crypto/evp/p_verify.c                      \
    crypto/evp/pbe_scrypt.c                    \
    crypto/evp/pmeth_check.c                   \
    crypto/evp/pmeth_gn.c                      \
    crypto/evp/pmeth_lib.c                     \
    crypto/evp/s_lib.c                         \
    crypto/evp/signature.c                     \
    crypto/evp/skeymgmt_meth.c

PKCS12_SRC := \
    crypto/pkcs12/p12_add.c  \
    crypto/pkcs12/p12_asn.c  \
    crypto/pkcs12/p12_attr.c \
    crypto/pkcs12/p12_crpt.c \
    crypto/pkcs12/p12_crt.c  \
    crypto/pkcs12/p12_decr.c \
    crypto/pkcs12/p12_init.c \
    crypto/pkcs12/p12_key.c  \
    crypto/pkcs12/p12_kiss.c \
    crypto/pkcs12/p12_mutl.c \
    crypto/pkcs12/p12_npas.c \
    crypto/pkcs12/p12_p8d.c  \
    crypto/pkcs12/p12_p8e.c  \
    crypto/pkcs12/p12_sbag.c \
    crypto/pkcs12/p12_utl.c  \
    crypto/pkcs12/pk12err.c

PKCS7_SRC := \
    crypto/pkcs7/bio_pk7.c   \
    crypto/pkcs7/pk7_asn1.c  \
    crypto/pkcs7/pk7_attr.c  \
    crypto/pkcs7/pk7_doit.c  \
    crypto/pkcs7/pk7_lib.c   \
    crypto/pkcs7/pk7_mime.c  \
    crypto/pkcs7/pk7_smime.c \
    crypto/pkcs7/pkcs7err.c

# ──────────────────────────────────────────────────────────
#  Core “utility” part of libcrypto – plain C sources only
# ──────────────────────────────────────────────────────────
CRYPTO_CORE_SRC := \
    crypto/asn1_dsa.c \
    crypto/bsearch.c \
    crypto/comp_methods.c \
    crypto/context.c \
    crypto/core_algorithm.c \
    crypto/core_fetch.c \
    crypto/core_namemap.c \
    crypto/cpt_err.c \
    crypto/cpuid.c \
    crypto/cryptlib.c \
    crypto/ctype.c \
    crypto/cversion.c \
    crypto/defaults.c \
    crypto/der_writer.c \
    crypto/deterministic_nonce.c \
    crypto/ebcdic.c \
    crypto/ex_data.c \
    crypto/getenv.c \
    crypto/indicator_core.c \
    crypto/info.c \
    crypto/init.c \
    crypto/initthread.c \
    crypto/mem.c \
    crypto/mem_clr.c \
    crypto/mem_sec.c \
    crypto/o_dir.c \
    crypto/o_fopen.c \
    crypto/o_init.c \
    crypto/o_str.c \
    crypto/o_time.c \
    crypto/packet.c \
    crypto/param_build.c \
    crypto/param_build_set.c \
    crypto/params.c \
    crypto/params_dup.c \
    crypto/params_from_text.c \
    crypto/passphrase.c \
    crypto/provider.c \
    crypto/provider_child.c \
    crypto/provider_conf.c \
    crypto/provider_core.c \
    crypto/provider_predefined.c \
    crypto/punycode.c \
    crypto/quic_vlint.c \
    crypto/self_test_core.c \
    crypto/sleep.c \
    crypto/sparse_array.c \
    crypto/ssl_err.c \
    crypto/threads_lib.c \
    crypto/threads_none.c \
    crypto/threads_pthread.c \
    crypto/threads_win.c \
    crypto/time.c \
    crypto/trace.c \
    crypto/uid.c

# ────────────────  “objects” sub-directory ────────────────
CRYPTO_OBJECTS_SRC := \
    crypto/objects/o_names.c \
    crypto/objects/obj_dat.c \
    crypto/objects/obj_err.c \
    crypto/objects/obj_lib.c \
    crypto/objects/obj_xref.c

CRYPTO_LHASH_SRC := \
    crypto/lhash/lh_stats.c \
    crypto/lhash/lhash.c

# ────────────────  “stack” sub-directory ────────────────
CRYPTO_STACK_SRC := \
    crypto/stack/stack.c

# ────────────────  “ui” (User-Interface) sub-directory ────────────────
CRYPTO_UI_SRC := \
    crypto/ui/ui_err.c      \
    crypto/ui/ui_lib.c      \
    crypto/ui/ui_null.c     \
    crypto/ui/ui_openssl.c  \
    crypto/ui/ui_util.c

# ────────────────  “property” sub-module (property subsystem) ────────────────
CRYPTO_PROPERTY_SRC := \
    crypto/property/defn_cache.c      \
    crypto/property/property.c        \
    crypto/property/property_err.c    \
    crypto/property/property_parse.c  \
    crypto/property/property_query.c  \
    crypto/property/property_string.c

# ───────────────────── Elliptic-Curve source lists ─────────────────────

# 1. Curve448 implementation (including EdDSA-448)
EC_CURVE448_SRC := \
    crypto/ec/curve448/arch_32/f_impl32.c          \
    crypto/ec/curve448/arch_64/f_impl64.c          \
    crypto/ec/curve448/curve448.c                  \
    crypto/ec/curve448/curve448_tables.c           \
    crypto/ec/curve448/eddsa.c                     \
    crypto/ec/curve448/f_generic.c                 \
    crypto/ec/curve448/scalar.c

# 2. General EC (secp{p256,p384,…}, Brainpool, etc.) + Curve25519 / X448
EC_CORE_SRC := \
    crypto/ec/curve25519.c           \
    crypto/ec/ec2_oct.c              \
    crypto/ec/ec2_smpl.c             \
    crypto/ec/ec_ameth.c             \
    crypto/ec/ec_asn1.c              \
    crypto/ec/ec_backend.c           \
    crypto/ec/ec_check.c             \
    crypto/ec/ec_curve.c             \
    crypto/ec/ec_cvt.c               \
    crypto/ec/ec_deprecated.c        \
    crypto/ec/ec_err.c               \
    crypto/ec/ec_key.c               \
    crypto/ec/ec_kmeth.c             \
    crypto/ec/ec_lib.c               \
    crypto/ec/ec_mult.c              \
    crypto/ec/ec_oct.c               \
    crypto/ec/ec_pmeth.c             \
    crypto/ec/ec_print.c             \
    crypto/ec/ecdh_kdf.c             \
    crypto/ec/ecdh_ossl.c            \
    crypto/ec/ecdsa_ossl.c           \
    crypto/ec/ecdsa_sign.c           \
    crypto/ec/ecdsa_vrf.c            \
    crypto/ec/eck_prn.c              \
    crypto/ec/ecp_mont.c             \
    crypto/ec/ecp_nist.c             \
    crypto/ec/ecp_oct.c              \
    crypto/ec/ecp_smpl.c             \
    crypto/ec/ecx_backend.c          \
    crypto/ec/ecx_key.c              \
    crypto/ec/ecx_meth.c


# ───────────────────── PEM & PVK source list ─────────────────────

PEM_SRC := \
    crypto/pem/pem_all.c   \
    crypto/pem/pem_err.c   \
    crypto/pem/pem_info.c  \
    crypto/pem/pem_lib.c   \
    crypto/pem/pem_oth.c   \
    crypto/pem/pem_pk8.c   \
    crypto/pem/pem_pkey.c  \
    crypto/pem/pem_sign.c  \
    crypto/pem/pem_x509.c  \
    crypto/pem/pem_xaux.c  \
    crypto/pem/pvkfmt.c

# ───────────────────── Random-number subsystem ─────────────────────
RAND_SRC := \
    crypto/rand/prov_seed.c      \
    crypto/rand/rand_deprecated.c\
    crypto/rand/rand_err.c       \
    crypto/rand/rand_lib.c       \
    crypto/rand/rand_meth.c      \
    crypto/rand/rand_pool.c      \
    crypto/rand/rand_uniform.c   \
    crypto/rand/randfile.c

# ───────────────────────── DES / 3-DES ──────────────────────────
# Object files come from the classic DES implementation (also used
# for 2-key / 3-key 3DES).  Below is the one-to-one mapping from
# .o files to their C sources so you can feed the list straight to
# SMACK or a normal compiler tool-chain.

DES_SRC := \
    crypto/des/cbc_cksm.c   \
    crypto/des/cbc_enc.c    \
    crypto/des/cfb64ede.c   \
    crypto/des/cfb64enc.c   \
    crypto/des/cfb_enc.c    \
    crypto/des/des_enc.c    \
    crypto/des/ecb3_enc.c   \
    crypto/des/ecb_enc.c    \
    crypto/des/fcrypt.c     \
    crypto/des/fcrypt_b.c   \
    crypto/des/ofb64ede.c   \
    crypto/des/ofb64enc.c   \
    crypto/des/ofb_enc.c    \
    crypto/des/pcbc_enc.c   \
    crypto/des/qud_cksm.c   \
    crypto/des/rand_key.c   \
    crypto/des/set_key.c    \
    crypto/des/str2key.c    \
    crypto/des/xcbc_enc.c

POLY1305_SRC := \
    crypto/poly1305/poly1305.c

# ──────────────────────── H M A C ────────────────────────
# Single translation unit that backs libcrypto-lib-hmac.o

HMAC_SRC := \
    crypto/hmac/hmac.c

# ──────────────── B L O C K   M O D E S  (CBC, CTR, GCM, …) ────────────────
# Object files              →            Translation units
# ────────────────────────────────────────────────────────────────────────────
MODES_SRC := \
    crypto/modes/cbc128.c      \
    crypto/modes/ccm128.c      \
    crypto/modes/cfb128.c      \
    crypto/modes/ctr128.c      \
    crypto/modes/cts128.c      \
    crypto/modes/gcm128.c      \
    crypto/modes/ocb128.c      \
    crypto/modes/ofb128.c      \
    crypto/modes/siv128.c      \
    crypto/modes/wrap128.c     \
    crypto/modes/xts128.c      \
    crypto/modes/xts128gb.c

# ─────────────────────  M D 5  digest code  ─────────────────────
# Object file                          →           C source file
# ---------------------------------------------------------------
MD5_SRC := \
    crypto/md5/md5_dgst.c   \
    crypto/md5/md5_one.c    \
    crypto/md5/md5_sha1.c

# ────────────────  E N C O D E  /  D E C O D E  ────────────────
# Object file                         →      C source
# ----------------------------------------------------------------
ENCDEC_SRC := \
    crypto/encode_decode/decoder_err.c    \
    crypto/encode_decode/decoder_lib.c    \
    crypto/encode_decode/decoder_meth.c   \
    crypto/encode_decode/decoder_pkey.c   \
    crypto/encode_decode/encoder_err.c    \
    crypto/encode_decode/encoder_lib.c    \
    crypto/encode_decode/encoder_meth.c   \
    crypto/encode_decode/encoder_pkey.c

# ─────────────────────  D i f f i e - H e l l m a n  ─────────────────────
# Object file                          →           C source file
# -----------------------------------------------------------------------
DH_SRC := \
    crypto/dh/dh_ameth.c          \
    crypto/dh/dh_asn1.c           \
    crypto/dh/dh_backend.c        \
    crypto/dh/dh_check.c          \
    crypto/dh/dh_depr.c           \
    crypto/dh/dh_err.c            \
    crypto/dh/dh_gen.c            \
    crypto/dh/dh_group_params.c   \
    crypto/dh/dh_kdf.c            \
    crypto/dh/dh_key.c            \
    crypto/dh/dh_lib.c            \
    crypto/dh/dh_meth.c           \
    crypto/dh/dh_pmeth.c          \
    crypto/dh/dh_prn.c            \
    crypto/dh/dh_rfc5114.c


# ────────────────────────  D . S . O .  layer  ─────────────────────────
# Dynamic-shared-object abstraction (loadable engines/providers, etc.)
# -----------------------------------------------------------------------
DSO_SRC := \
    crypto/dso/dso_dl.c           \
    crypto/dso/dso_dlfcn.c        \
    crypto/dso/dso_err.c          \
    crypto/dso/dso_lib.c          \
    crypto/dso/dso_openssl.c      \
    crypto/dso/dso_vms.c          \
    crypto/dso/dso_win32.c

# ───────────────────────  O p e n S S L   S T O R E  ───────────────────────
# Object file                           →             Canonical C source
# --------------------------------------------------------------------------
STORE_SRC := \
    crypto/store/store_err.c          \
    crypto/store/store_init.c         \
    crypto/store/store_lib.c          \
    crypto/store/store_meth.c         \
    crypto/store/store_register.c     \
    crypto/store/store_result.c       \
    crypto/store/store_strings.c

# ─────────────────────  F F C   (Finite-Field Crypto)  ─────────────────────
# Object file                           →                 C source file
# --------------------------------------------------------------------------
FFC_SRC := \
    crypto/ffc/ffc_backend.c             \
    crypto/ffc/ffc_dh.c                  \
    crypto/ffc/ffc_key_generate.c        \
    crypto/ffc/ffc_key_validate.c        \
    crypto/ffc/ffc_params.c              \
    crypto/ffc/ffc_params_generate.c     \
    crypto/ffc/ffc_params_validate.c

# ───────────────────────────────────────────
#  Camellia, ChaCha, and CONF subsystem C files
# ───────────────────────────────────────────

# ▒▒ Camellia (symmetric cipher) ▒▒
CAMELLIA_SRC := \
    crypto/camellia/camellia.c          \
    crypto/camellia/cmll_cbc.c          \
    crypto/camellia/cmll_cfb.c          \
    crypto/camellia/cmll_ctr.c          \
    crypto/camellia/cmll_ecb.c          \
    crypto/camellia/cmll_misc.c         \
    crypto/camellia/cmll_ofb.c

# ▒▒ ChaCha (stream cipher) ▒▒
CHACHA_SRC := \
    crypto/chacha/chacha_enc.c

# ▒▒ CONF (OpenSSL configuration parser) ▒▒
CONF_SRC := \
    crypto/conf/conf_api.c              \
    crypto/conf/conf_def.c              \
    crypto/conf/conf_err.c              \
    crypto/conf/conf_lib.c              \
    crypto/conf/conf_mall.c             \
    crypto/conf/conf_mod.c              \
    crypto/conf/conf_sap.c              \
    crypto/conf/conf_ssl.c

BUFFER_SRC := \
    crypto/buffer/buf_err.c  \
    crypto/buffer/buffer.c

# All provider-side .c files that correspond to your list of *.o objects
PROVIDER_ALL_SRC := \
    providers/baseprov.c \
    providers/defltprov.c \
    providers/nullprov.c \
    providers/prov_running.c \
    providers/common/der/der_rsa_sig.c \
    providers/common/bio_prov.c \
    providers/common/capabilities.c \
    providers/common/digest_to_nid.c \
    providers/common/provider_seeding.c \
    providers/common/provider_util.c \
    providers/common/securitycheck.c \
    providers/common/securitycheck_default.c \
    providers/implementations/asymciphers/rsa_enc.c \
    providers/implementations/ciphers/cipher_aes.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha1_etm_hw.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha1_hw.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha256_etm_hw.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha256_hw.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha512_etm_hw.c \
    providers/implementations/ciphers/cipher_aes_cbc_hmac_sha_etm.c \
    providers/implementations/ciphers/cipher_aes_ccm.c \
    providers/implementations/ciphers/cipher_aes_ccm_hw.c \
    providers/implementations/ciphers/cipher_aes_gcm.c \
    providers/implementations/ciphers/cipher_aes_gcm_hw.c \
    providers/implementations/ciphers/cipher_aes_hw.c \
    providers/implementations/ciphers/cipher_aes_wrp.c \
    providers/implementations/ciphers/cipher_aes_xts.c \
    providers/implementations/ciphers/cipher_aes_xts_fips.c \
    providers/implementations/ciphers/cipher_aes_xts_hw.c \
    providers/implementations/ciphers/cipher_aria.c \
    providers/implementations/ciphers/cipher_aria_ccm.c \
    providers/implementations/ciphers/cipher_aria_ccm_hw.c \
    providers/implementations/ciphers/cipher_aria_gcm.c \
    providers/implementations/ciphers/cipher_aria_gcm_hw.c \
    providers/implementations/ciphers/cipher_aria_hw.c \
    providers/implementations/ciphers/cipher_camellia.c \
    providers/implementations/ciphers/cipher_camellia_hw.c \
    providers/implementations/ciphers/cipher_chacha20.c \
    providers/implementations/ciphers/cipher_chacha20_hw.c \
    providers/implementations/ciphers/cipher_chacha20_poly1305.c \
    providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c \
    providers/implementations/ciphers/cipher_cts.c \
    providers/implementations/ciphers/cipher_null.c \
    providers/implementations/ciphers/cipher_tdes.c \
    providers/implementations/ciphers/cipher_tdes_common.c \
    providers/implementations/ciphers/cipher_tdes_default.c \
    providers/implementations/ciphers/cipher_tdes_default_hw.c \
    providers/implementations/ciphers/cipher_tdes_hw.c \
    providers/implementations/ciphers/cipher_tdes_wrap.c \
    providers/implementations/ciphers/cipher_tdes_wrap_hw.c \
    providers/implementations/digests/md5_prov.c \
    providers/implementations/digests/md5_sha1_prov.c \
    providers/implementations/digests/null_prov.c \
    providers/implementations/digests/sha2_prov.c \
    providers/implementations/digests/sha3_prov.c \
    providers/implementations/encode_decode/decode_der2key.c \
    providers/implementations/encode_decode/decode_epki2pki.c \
    providers/implementations/encode_decode/decode_msblob2key.c \
    providers/implementations/encode_decode/decode_pem2der.c \
    providers/implementations/encode_decode/decode_pvk2key.c \
    providers/implementations/encode_decode/decode_spki2typespki.c \
    providers/implementations/encode_decode/encode_key2any.c \
    providers/implementations/encode_decode/encode_key2blob.c \
    providers/implementations/encode_decode/encode_key2ms.c \
    providers/implementations/encode_decode/encode_key2text.c \
    providers/implementations/encode_decode/endecoder_common.c \
    providers/implementations/encode_decode/ml_common_codecs.c \
    providers/implementations/encode_decode/ml_dsa_codecs.c \
    providers/implementations/encode_decode/ml_kem_codecs.c \
    providers/implementations/exchange/dh_exch.c \
    providers/implementations/exchange/ecdh_exch.c \
    providers/implementations/exchange/ecx_exch.c \
    providers/implementations/exchange/kdf_exch.c \
    providers/implementations/kdfs/argon2.c \
    providers/implementations/kdfs/hkdf.c \
    providers/implementations/kdfs/hmacdrbg_kdf.c \
    providers/implementations/kdfs/kbkdf.c \
    providers/implementations/kdfs/krb5kdf.c \
    providers/implementations/kdfs/pbkdf2.c \
    providers/implementations/kdfs/pbkdf2_fips.c \
    providers/implementations/kdfs/pkcs12kdf.c \
    providers/implementations/kdfs/scrypt.c \
    providers/implementations/kdfs/sshkdf.c \
    providers/implementations/kdfs/sskdf.c \
    providers/implementations/kdfs/tls1_prf.c \
    providers/implementations/kdfs/x942kdf.c \
    providers/implementations/kem/ec_kem.c \
    providers/implementations/kem/ecx_kem.c \
    providers/implementations/kem/kem_util.c \
    providers/implementations/kem/ml_kem_kem.c \
    providers/implementations/kem/mlx_kem.c \
    providers/implementations/kem/rsa_kem.c \
    providers/implementations/keymgmt/dh_kmgmt.c \
    providers/implementations/keymgmt/ec_kmgmt.c \
    providers/implementations/keymgmt/ecx_kmgmt.c \
    providers/implementations/keymgmt/kdf_legacy_kmgmt.c \
    providers/implementations/keymgmt/mac_legacy_kmgmt.c \
    providers/implementations/keymgmt/ml_dsa_kmgmt.c \
    providers/implementations/keymgmt/ml_kem_kmgmt.c \
    providers/implementations/keymgmt/mlx_kmgmt.c \
    providers/implementations/keymgmt/rsa_kmgmt.c \
    providers/implementations/keymgmt/slh_dsa_kmgmt.c \
    providers/implementations/macs/gmac_prov.c \
    providers/implementations/macs/hmac_prov.c \
    providers/implementations/macs/kmac_prov.c \
    providers/implementations/macs/poly1305_prov.c \
    providers/implementations/rands/drbg.c \
    providers/implementations/rands/drbg_ctr.c \
    providers/implementations/rands/drbg_hash.c \
    providers/implementations/rands/drbg_hmac.c \
    providers/implementations/rands/seed_src.c \
    providers/implementations/rands/seed_src_jitter.c \
    providers/implementations/rands/test_rng.c \
    providers/implementations/rands/seeding/rand_cpu_x86.c \
    providers/implementations/rands/seeding/rand_tsc.c \
    providers/implementations/rands/seeding/rand_unix.c \
    providers/implementations/rands/seeding/rand_win.c \
    providers/implementations/signature/ecdsa_sig.c \
    providers/implementations/signature/eddsa_sig.c \
    providers/implementations/signature/mac_legacy_sig.c \
    providers/implementations/signature/ml_dsa_sig.c \
    providers/implementations/signature/rsa_sig.c \
    providers/implementations/signature/slh_dsa_sig.c \
    providers/implementations/skeymgmt/aes_skmgmt.c \
    providers/implementations/skeymgmt/generic.c \
    providers/implementations/storemgmt/file_store.c \
    providers/implementations/storemgmt/file_store_any2obj.c \
    ssl/record/methods/ssl3_cbc.c \
    providers/common/der/der_digests_gen.c \
    providers/common/der/der_ec_gen.c \
    providers/common/der/der_ec_key.c \
    providers/common/der/der_ec_sig.c \
    providers/common/der/der_ecx_gen.c \
    providers/common/der/der_ecx_key.c \
    providers/common/der/der_ml_dsa_gen.c \
    providers/common/der/der_ml_dsa_key.c \
    providers/common/der/der_rsa_gen.c \
    providers/common/der/der_rsa_key.c \
    providers/common/der/der_slh_dsa_gen.c \
    providers/common/der/der_slh_dsa_key.c \
    providers/common/der/der_wrap_gen.c \
    providers/common/provider_ctx.c \
    providers/common/provider_err.c \
    providers/implementations/ciphers/ciphercommon.c \
    providers/implementations/ciphers/ciphercommon_block.c \
    providers/implementations/ciphers/ciphercommon_ccm.c \
    providers/implementations/ciphers/ciphercommon_ccm_hw.c \
    providers/implementations/ciphers/ciphercommon_gcm.c \
    providers/implementations/ciphers/ciphercommon_gcm_hw.c \
    providers/implementations/ciphers/ciphercommon_hw.c \
    providers/implementations/digests/digestcommon.c \
    ssl/record/methods/tls_pad.c

HTTP_SRC := crypto/http/http_lib.c
ARIA_SRC := crypto/aria/aria.c

HASHTABLE_SRC := \
    crypto/hashtable/hashfunc.c \
    crypto/hashtable/hashtable.c

ML_DSA_SRC := \
    crypto/ml_dsa/ml_dsa_encoders.c \
    crypto/ml_dsa/ml_dsa_key.c \
    crypto/ml_dsa/ml_dsa_key_compress.c \
    crypto/ml_dsa/ml_dsa_matrix.c \
    crypto/ml_dsa/ml_dsa_ntt.c \
    crypto/ml_dsa/ml_dsa_params.c \
    crypto/ml_dsa/ml_dsa_sample.c \
    crypto/ml_dsa/ml_dsa_sign.c

HPKE_SRC := \
    crypto/hpke/hpke.c \
    crypto/hpke/hpke_util.c

ML_KEM_SRC := \
    crypto/ml_kem/ml_kem.c

LIBCRYPTO_SRC := $(BIO_SRC) \
              $(CRYPTO_SRC) \
              $(AES_SRC) \
              $(OPENSSL_ASN1_SRC) \
              $(OPENSSL_ASYNC_SRC) \
              $(X509_SRC) \
              $(RSA_SRC) \
              $(SEED_SRC) \
              $(SHA_SRC) \
              $(SLH_DSA_SRC) \
              $(BN_SRC) \
              $(ERR_SRC) \
              $(ESS_SRC) \
              $(EVP_SRC) \
              $(PKCS12_SRC) \
              $(PKCS7_SRC) \
              $(CRYPTO_CORE_SRC) \
              $(CRYPTO_OBJECTS_SRC) \
              $(CRYPTO_LHASH_SRC) \
              $(CRYPTO_STACK_SRC) \
              $(CRYPTO_UI_SRC) \
              $(CRYPTO_PROPERTY_SRC) \
              $(EC_CURVE448_SRC) \
              $(EC_CORE_SRC) \
              $(PEM_SRC) \
              $(RAND_SRC) \
              $(POLY1305_SRC) \
              $(DES_SRC) \
              $(MODES_SRC) \
              $(HMAC_SRC) \
              $(ENCDEC_SRC) \
              $(MD5_SRC) \
              $(DH_SRC) \
              $(DSO_SRC) \
              $(STORE_SRC) \
              $(FFC_SRC) \
              $(CAMELLIA_SRC) \
              $(CHACHA_SRC) \
              $(CONF_SRC) \
              $(BUFFER_SRC) \
              $(IMPLEMENTATION_RANDS_SRC) \
              $(DER_COMMON_SRC) \
              $(HTTP_SRC) \
              $(PROV_COMMON_DEFAULT_SRC) \
              $(HASHTABLE_SRC) \
              $(ARIA_SRC) \
              $(PROVIDER_ALL_SRC) \
              $(ML_DSA_SRC) \
              $(HPKE_SRC) \
              $(ML_KEM_SRC)

WRAPPER      := handshake_wrapper.c          # your driver that calls SSL_do_handshake


# final bit-code module after linking + DCE
HANDSHAKE_BC := handshake.bc

# ---------------------------------------------------------------------------
# 3.  Build rules
# ---------------------------------------------------------------------------
all: handshake

handshake: $(LIBSSL_SRC) $(LIBCRYPTO_SRC)
	$(SMACK) $(SMACK_FLAGS) --clang-options="-I. -Iinclude" main.c $(LIBSSL_SRC) $(LIBCRYPTO_SRC) -bpl handshake.bpl
	

APP_FLAGS = -DOPENSSLDIR=\"/tmp/openssl\" \
                   -DENGINESDIR=\"/tmp/openssl/engines\" \
                   -DMODULESDIR=\"/tmp/openssl/modules\"

INCLUDE_DIRS = -I. -Iinclude -Iproviders/common/include -Iproviders/implementations/include -Iproviders/implementations/include -Iproviders/common/include -Iproviders/fips/include

handshake_native: $(LIBSSL_SRC) $(LIBCRYPTO_SRC)
	gcc -DTEST -DCOMPILE $(APP_FLAGS) $(INCLUDE_DIRS) main.c $(LIBSSL_SRC) $(LIBCRYPTO_SRC) -o handshake

# ssl/libssl-lib-pqueue.o: ssl/pqueue.c
# 	$(SMACK) --clang-options="-I. -Iinclude" ssl/pqueue.c $(SMACK_FLAGS)  -bpl ssl/libssl-lib-pqueue.bpl

# ---------------------------------------------------------------------------
# 4.  House-keeping
# ---------------------------------------------------------------------------
clean:
	rm -f $(OPENSSL_BC) $(WRAPPER_BC) $(HANDSHAKE_BC) all.bc handshake.bpl

.PHONY: all handshake clean