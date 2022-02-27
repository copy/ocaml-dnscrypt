exception Wrong_key_size

(*
external caml_tweetnacl_poly1305 :
  Cstruct.buffer -> Cstruct.buffer -> int64 -> Cstruct.buffer -> unit
  = "caml_tweetnacl_poly1305"

let poly1305 ~key msg =
  let poly1305_key_length = 32 in
  let poly1305_output_length = 16 in
  if Cstruct.len key <> poly1305_key_length then raise Wrong_key_size;
  let key_buffer = Cstruct.to_bigarray key in
  let result = Cstruct.create poly1305_output_length in
  let result_buffer = Cstruct.to_bigarray result in
  let msg_len = Int64.of_int @@ Cstruct.len msg in
  let msg_buffer = Cstruct.to_bigarray msg in
  caml_tweetnacl_poly1305 result_buffer msg_buffer msg_len key_buffer;
  result
*)

(*
external crypto_box : message:string -> nonce:string -> public_key:string -> private_key:string -> string = " caml_tweetnacl_crypto_box"
external crypto_box_open : cipher:string -> nonce:string -> public_key:string -> private_key:string -> string = " caml_tweetnacl_crypto_box_open"
*)

external crypto_box_create_keypair : string -> string = "caml_tweetnacl_crypto_box_create_keypair"

external crypto_box_beforenm : public_key:string -> private_key:string -> string = "caml_tweetnacl_crypto_box_beforenm"
external crypto_box_afternm : message:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_afternm"
external crypto_box_open_afternm : cipher:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_open_afternm"

external crypto_box_beforenm_chacha : public_key:string -> private_key:string -> string = "caml_tweetnacl_crypto_box_beforenm_chacha"
external crypto_box_afternm_chacha : message:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_afternm_chacha"
external crypto_box_open_afternm_chacha : cipher:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_open_afternm_chacha"

external sign_open : message:string -> public_key:string -> bool = "caml_tweetnacl_sign_open"
let verify ~signature ~message ~public_key =
  let message = String.concat "" [signature; message] in
  sign_open ~message ~public_key
