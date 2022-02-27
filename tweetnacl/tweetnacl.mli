exception Wrong_key_size

(* val poly1305 : key:Cstruct.t -> Cstruct.t -> Cstruct.t *)
(* val crypto_box : message:string -> nonce:string -> public_key:string -> private_key:string -> string *)
(* val crypto_box_open : cipher:string -> nonce:string -> public_key:string -> private_key:string -> string *)

external crypto_box_create_keypair : string -> string = "caml_tweetnacl_crypto_box_create_keypair"

external crypto_box_beforenm : public_key:string -> private_key:string -> string = "caml_tweetnacl_crypto_box_beforenm"
external crypto_box_afternm : message:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_afternm"
external crypto_box_open_afternm : cipher:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_open_afternm"

external crypto_box_beforenm_chacha : public_key:string -> private_key:string -> string = "caml_tweetnacl_crypto_box_beforenm_chacha"
external crypto_box_afternm_chacha : message:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_afternm_chacha"
external crypto_box_open_afternm_chacha : cipher:string -> nonce:string -> key:string -> string = "caml_tweetnacl_crypto_box_open_afternm_chacha"

val verify : signature:string -> message:string -> public_key:string -> bool
