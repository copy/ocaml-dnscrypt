#include "caml/memory.h"
#include "caml/bigarray.h"

#include <caml/mlvalues.h>
#include <caml/alloc.h>

#include <assert.h>
#include "tweetnacl.h"

//void randombytes(unsigned char *buf, unsigned int n)
//{
//   abort();
//}

//CAMLprim value caml_tweetnacl_poly1305(value into, value m, value n, value k)
//{
//   CAMLparam4(into, m, n, k);
//
//   crypto_onetimeauth_poly1305(
//      Caml_ba_data_val(into),
//      Caml_ba_data_val(m),
//      Int64_val(n),
//      Caml_ba_data_val(k)
//   );
//
//   CAMLreturn(Val_unit);
//}

//CAMLprim value caml_tweetnacl_crypto_box(value message, value nonce, value public_key, value secret_key)
//{
//    CAMLparam4(message, nonce, public_key, secret_key);
//    CAMLlocal1(cipher);
//
//    cipher = caml_alloc_string(caml_string_length(message));
//    int ok = crypto_box(Bytes_val(cipher), String_val(message), caml_string_length(message), String_val(nonce), String_val(public_key), String_val(secret_key));
//    assert(ok >= 0);
//
//    CAMLreturn(cipher);
//}
//
//CAMLprim value caml_tweetnacl_crypto_box_open(value cipher, value nonce, value public_key, value secret_key)
//{
//    CAMLparam4(cipher, nonce, public_key, secret_key);
//    CAMLlocal1(message);
//
//    message = caml_alloc_string(caml_string_length(cipher));
//    int ok = crypto_box_open(Bytes_val(message), String_val(cipher), caml_string_length(cipher), String_val(nonce), String_val(public_key), String_val(secret_key));
//    assert(ok >= 0);
//
//    CAMLreturn(message);
//}


CAMLprim value caml_tweetnacl_crypto_box_create_keypair(value key)
{
    CAMLparam1(key);
    CAMLlocal1(other_key);
    other_key = caml_alloc_string(32);
    crypto_box_keypair(Bytes_val(other_key), Bytes_val(key));
    CAMLreturn(other_key);
}


CAMLprim value caml_tweetnacl_crypto_box_beforenm(value public_key, value private_key)
{
    CAMLparam2(public_key, private_key);
    CAMLlocal1(shared_key);
    shared_key = caml_alloc_string(32);
    crypto_box_beforenm(Bytes_val(shared_key), String_val(public_key), String_val(private_key));
    CAMLreturn(shared_key);
}

CAMLprim value caml_tweetnacl_crypto_box_afternm(value message, value nonce, value key)
{
    CAMLparam3(message, nonce, key);
    CAMLlocal1(cipher);
    cipher = caml_alloc_string(caml_string_length(message));
    int ok = crypto_box_afternm(Bytes_val(cipher), String_val(message), caml_string_length(message), String_val(nonce), String_val(key));
    assert(ok != -1);
    CAMLreturn(cipher);
}

CAMLprim value caml_tweetnacl_crypto_box_open_afternm(value cipher, value nonce, value key)
{
    CAMLparam3(cipher, nonce, key);
    CAMLlocal1(message);
    message = caml_alloc_string(caml_string_length(cipher));
    int ok = crypto_box_open_afternm(Bytes_val(message), String_val(cipher), caml_string_length(cipher), String_val(nonce), String_val(key));
    assert(ok != -1);
    CAMLreturn(message);
}

extern int crypto_box_beforenm_chacha(unsigned char *k,const unsigned char *y,const unsigned char *x);

CAMLprim value caml_tweetnacl_crypto_box_beforenm_chacha(value public_key, value private_key)
{
    CAMLparam2(public_key, private_key);
    CAMLlocal1(shared_key);
    shared_key = caml_alloc_string(32);
    crypto_box_beforenm_chacha(Bytes_val(shared_key), String_val(public_key), String_val(private_key));
    CAMLreturn(shared_key);
}

extern int crypto_box_afternm_chacha(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

CAMLprim value caml_tweetnacl_crypto_box_afternm_chacha(value message, value nonce, value key)
{
    CAMLparam3(message, nonce, key);
    CAMLlocal1(cipher);
    cipher = caml_alloc_string(caml_string_length(message));
    int ok = crypto_box_afternm_chacha(Bytes_val(cipher), String_val(message), caml_string_length(message), String_val(nonce), String_val(key));
    if(ok == -1) abort();
    CAMLreturn(cipher);
}

extern int crypto_box_open_afternm_chacha(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

CAMLprim value caml_tweetnacl_crypto_box_open_afternm_chacha(value cipher, value nonce, value key)
{
    CAMLparam3(cipher, nonce, key);
    CAMLlocal1(message);
    message = caml_alloc_string(caml_string_length(cipher));
    int ok = crypto_box_open_afternm_chacha(Bytes_val(message), String_val(cipher), caml_string_length(cipher), String_val(nonce), String_val(key));
    if(ok == -1) abort();
    CAMLreturn(message);
}



CAMLprim value caml_tweetnacl_sign_open(value message, value public_key)
{
    CAMLparam2(message, public_key);
    CAMLlocal1(out_message);
    long long int unused = 0;
    out_message = caml_alloc_string(caml_string_length(message));
    int result = crypto_sign_open(Bytes_val(out_message), &unused, String_val(message), caml_string_length(message), Bytes_val(public_key));
    CAMLreturn(Val_bool(result == 0));
}
