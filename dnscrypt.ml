(* https://dnscrypt.info/protocol/ *)

let (let*) = Result.bind

let strip_sdns_prefix sdns =
  let sdns_prefix = "sdns://" in
  if String.starts_with ~prefix:sdns_prefix sdns then
    Ok (String.sub sdns (String.length sdns_prefix) (String.length sdns - String.length sdns_prefix))
  else
    Error `Invalid_prefix

type sdns =
  | DnsCrypt of { props: int64; addr: string; port: int; public_key: string; provider_name: string }
  | Doh
  | DnsOverTls
  | DnsCryptRelay
  | PlainDns
  | Other
let show_sdns = function
  | DnsCrypt { props; addr; port; public_key; provider_name } ->
    Printf.sprintf "DnsCrypt { props=%Ld; addr=%s:%d public_key=\"%S\" provider_name=\"%s\" }"
      props addr port public_key provider_name
  | Doh -> "Doh"
  | DnsOverTls -> "DnsOverTls"
  | DnsCryptRelay -> "DnsCryptRelay"
  | PlainDns -> "PlainDns"
  | Other -> "Other"

type parse_sdns_error = [
   | `Base64_error of string
   | `Invalid_host of string
   | `Invalid_prefix
   | `Invalid_public_key_length
   | `Trailing_garbage
   | `Unknown_stamp_id of int]

let decode_base64 x =
  match Base64.decode ~alphabet:Base64.uri_safe_alphabet ~pad:false x with
  | Ok _ as ok -> ok
  | Error (`Msg m) -> Error (`Base64_error m)

let parse_host_and_optional_port ~default_port addr =
  match String.split_on_char ':' addr with
  | [address] ->
    Ok (address, default_port)
  | [address; port] ->
    (match int_of_string_opt port with
     | Some port -> Ok (address, port)
     | None -> Error (`Invalid_host addr))
  | _ ->
    Error (`Invalid_host addr)

let parse_sdns sdns =
  (* angstrom *)
  let* sdns = strip_sdns_prefix sdns in
  let* stamp = decode_base64 sdns in
  let stamp = Bytes.of_string stamp in
  let id = Bytes.get_uint8 stamp 0 in
  let length_prefixed_string offset =
    let length = Bytes.get_uint8 stamp offset in
    offset + 1 + length, Bytes.sub_string stamp (offset + 1) length
  in
  match id with
   | 0x00 ->
     Ok PlainDns
   | 0x01 ->
     let props = Bytes.get_int64_le stamp 1 in
     let offset, addr_and_port = length_prefixed_string 9 in
     let offset, public_key = length_prefixed_string offset in
     let offset, provider_name = length_prefixed_string offset in
     let* (addr, port) = parse_host_and_optional_port ~default_port:443 addr_and_port in
     if offset <> Bytes.length stamp then
       Error `Trailing_garbage
     else if String.length public_key <> 32 then
       Error `Invalid_public_key_length
     else
       Ok (DnsCrypt { props; addr; port; public_key; provider_name })
   | 0x02 -> Ok Doh
   | 0x03 -> Ok DnsOverTls
   | 0x81 -> Ok DnsCryptRelay
   | _ -> Error (`Unknown_stamp_id id)

let of_hex s =
  let len = String.length s in
  assert (len mod 2 = 0);
  let buffer = String.init (String.length s / 2) (fun i ->
      int_of_string ("0x" ^ String.make 1 s.[i*2] ^ String.make 1 s.[i*2+1]) |> Char.chr
    )
  in
  buffer

let hex s =
  let b = Buffer.create (2 * String.length s) in
  String.iter begin fun c ->
    Buffer.add_string b @@ Printf.sprintf "%02x" @@ Char.code c
  end s;
  Buffer.contents b

module type Crypto = sig
  val create_shared_key : public_key:string -> private_key:string -> string
  val encrypt : shared_key:string -> nonce:string -> message:string -> string
  val decrypt : shared_key:string -> nonce:string -> cipher:string -> string
end

module Salsa20_tweetnacl = struct
  let create_shared_key ~public_key ~private_key =
    Tweetnacl.crypto_box_beforenm ~private_key ~public_key

  let encrypt ~shared_key ~nonce ~message =
    let message = String.concat "" [
        String.make 32 '\x00';
        message;
      ]
    in
    let cipher = Tweetnacl.crypto_box_afternm ~message ~nonce ~key:shared_key in
    String.sub cipher 16 (String.length cipher - 16)

  let decrypt ~shared_key ~nonce ~cipher =
    let cipher = String.concat "" [
        String.make 16 '\x00';
        cipher;
      ]
    in
    let message = Tweetnacl.crypto_box_open_afternm ~cipher ~nonce ~key:shared_key in
    String.sub message 32 (String.length message - 32)
end

(*
module Salsa20_hacl : Crypto = struct
  let create_shared_key ~public_key ~private_key =
    Hacl.Box.dh
      (Hacl.Box.unsafe_pk_of_bytes @@ Bigstring.of_string public_key)
      (Hacl.Box.unsafe_sk_of_bytes @@ Bigstring.of_string private_key)
    |> Hacl.Box.unsafe_to_bytes |> Bigstring.to_string

  let encrypt ~shared_key ~nonce ~message =
    let message = String.concat "" [
        String.make 32 '\x00';
        message;
      ]
    in
    let cmsg = Bigstring.create (String.length message) in
    Hacl.Box.box
      ~k:(Hacl.Box.unsafe_ck_of_bytes @@ Bigstring.of_string shared_key)
      ~nonce:(Bigstring.of_string nonce)
      ~msg:(Bigstring.of_string message)
      ~cmsg;
    Bigstring.sub_string cmsg 16 (Bigstring.length cmsg - 16)

  let decrypt ~shared_key ~nonce ~cipher =
    let cipher = String.concat "" [
        String.make 16 '\x00';
        cipher;
      ]
    in
    let msg = Bigstring.create (String.length cipher) in
    if Hacl.Box.box_open
        ~k:(Hacl.Box.unsafe_ck_of_bytes @@ Bigstring.of_string shared_key)
        ~nonce:(Bigstring.of_string nonce)
        ~cmsg:(Bigstring.of_string cipher)
        ~msg
    then
      Bigstring.sub_string msg 32 (Bigstring.length msg - 32)
    else
      ""

  let _selftest () =
    let msg = Bigstring.concat "" [
        Bigstring.make 32 '\x00';
        Bigstring.of_string "foobar";
      ] in
    let public_key, secret_key = Hacl.Box.keypair () in
    let k = Hacl.Box.dh public_key secret_key in
    let nonce = Bigstring.of_string "abcdefgerjtelirtj3ieotj3i4otj3i4otn34itn34it" in
    let cmsg = Bigstring.create (Bigstring.length msg) in
    Hacl.Box.box ~k ~nonce ~msg ~cmsg;
    print_endline @@ hex @@ Bigstring.to_string cmsg;
    (* let cmsg = Bigstring.sub cmsg 16 (Bigstring.length cmsg - 16) in *)
    (* print_endline @@ hex @@ Bigstring.to_string cmsg; *)
    let msg' = Bigstring.create (Bigstring.length cmsg) in
    assert (Hacl.Box.box_open ~k ~nonce ~cmsg ~msg:msg');
    print_endline @@ Bigstring.to_string msg';
    exit 42
end
*)

(*
module Salsa20_hacl2 : Crypto = struct
  module Salsa20 = Hacl_star.Hacl.NaCl

  let create_shared_key ~public_key ~private_key =
    let public_key = Bytes.of_string public_key in
    let private_key = Bytes.of_string private_key in
    let result = Bytes.create 32 in
    let r = Salsa20.box_beforenm result public_key private_key in
    assert r;
    Bytes.to_string result

  (* https://doc.libsodium.org/public-key_cryptography/authenticated_encryption *)
  let encrypt ~shared_key ~nonce ~message =
    let cipher = Bytes.create (16 + String.length message) in
    let message = Bytes.of_string message in
    let nonce = Bytes.of_string nonce in
    let shared_key = Bytes.of_string shared_key in
    let r = Salsa20.Easy.box_afternm cipher message nonce shared_key in
    assert r;
    Bytes.to_string cipher

  let decrypt ~shared_key ~nonce ~cipher =
    let message = Bytes.create (String.length cipher - 16) in
    let cipher = Bytes.of_string cipher in
    let nonce = Bytes.of_string nonce in
    let shared_key = Bytes.of_string shared_key in
    let r = Salsa20.Easy.box_open_afternm message cipher nonce shared_key in
    assert r;
    Bytes.to_string message
end
*)

module Chacha20_tweetnacl = struct
  let create_shared_key ~public_key ~private_key =
    Tweetnacl.crypto_box_beforenm_chacha ~private_key ~public_key

  let encrypt ~shared_key ~nonce ~message =
    let message = String.concat "" [
        String.make 32 '\x00';
        message;
      ]
    in
    let cipher = Tweetnacl.crypto_box_afternm_chacha ~message ~nonce ~key:shared_key in
    String.sub cipher 16 (String.length cipher - 16)

  let decrypt ~shared_key ~nonce ~cipher =
    let cipher = String.concat "" [
        String.make 16 '\x00';
        cipher;
      ]
    in
    let message = Tweetnacl.crypto_box_open_afternm_chacha ~cipher ~nonce ~key:shared_key in
    String.sub message 32 (String.length message - 32)
end

let _selftest_key_exchange rand =
  let private_key1 = rand 32 |> Bytes.to_string in
  let private_key2 = rand 32 |> Bytes.to_string in
  let public_key1 = Tweetnacl.crypto_box_create_keypair private_key1 in
  let public_key2 = Tweetnacl.crypto_box_create_keypair private_key2 in
  let shared_key12 = Tweetnacl.crypto_box_beforenm ~private_key:private_key1 ~public_key:public_key2 in
  let shared_key21 = Tweetnacl.crypto_box_beforenm ~private_key:private_key2 ~public_key:public_key1 in
  assert (shared_key12 = shared_key21)

type cert = {
  encryption_system: [`XSalsa20Poly1305 | `XChacha20Poly1305];
  resolver_shortterm_public_key: string;
  client_magic: string;
  serial: int;
  ts_start: int;
  ts_end: int;
}
let show_cert {
    encryption_system;
    resolver_shortterm_public_key;
    client_magic;
    serial;
    ts_start;
    ts_end; } =
  Printf.sprintf "{ encryption_system = %s; public_key = %S; client_magic = %S; serial = %d; ts_start = %s; ts_end = %s }"
    (match encryption_system with `XSalsa20Poly1305 -> "XSalsa20Poly1305" | `XChacha20Poly1305  -> "XChacha20Poly1305")
    resolver_shortterm_public_key
    client_magic
    serial
    (Ptime.of_float_s (Int.to_float ts_start) |> Option.get |> Ptime.to_rfc3339)
    (Ptime.of_float_s (Int.to_float ts_end) |> Option.get |> Ptime.to_rfc3339)

type cert_error = [
  | `Bad_magic
  | `Certificate_verification_failed
  | `Invalid_encryption_system_id]
type fetch_error = [
  | `Bad_dns_response of Dns.Packet.err
  | `Cert_timeout
  | `No_cert
  | `No_connection
  | `Non_answer_response of Dns.Packet.data
  | `Truncated]

let parse_cert cert resolver_public_key =
  (* angstrom *)
  let cert_magic = Bytes.sub_string cert 0 4 in
  let* () = if cert_magic = "DNSC" then Ok () else Error `Bad_magic in
  let* encryption_system = match Bytes.get_uint16_be cert 4 with
    | 0x00_01 -> Ok `XSalsa20Poly1305
    | 0x00_02 -> Ok `XChacha20Poly1305
    | _ -> Error `Invalid_encryption_system_id
  in
  let protocol_minor_version = Bytes.get_uint16_be cert 6 in
  let* () = if protocol_minor_version = 0 then Ok () else Error `Bad_magic in
  let signature = Bytes.sub_string cert 8 64 in
  let body = Bytes.sub_string cert 72 (Bytes.length cert - 72) in
  assert (String.length resolver_public_key = 32);
  let resolver_public_key =
    if false then ( (* inject fault *)
      let modified = Bytes.of_string resolver_public_key in
      Bytes.set_int8 modified 0 123;
      Bytes.to_string modified
    )
    else
      resolver_public_key
  in
  (* let* () =
    let key = match Mirage_crypto_ec.Ed25519.pub_of_cstruct (Cstruct.of_string resolver_public_key) with Error _ -> assert false | Ok k -> k in
    if Mirage_crypto_ec.Ed25519.verify ~key (Cstruct.of_string signature) ~msg:(Cstruct.of_string body)
    then Ok ()
    else Error `Certificate_verification_failed
  in *)
  let* () = if Tweetnacl.verify ~signature ~message:body ~public_key:resolver_public_key then Ok () else Error `Certificate_verification_failed in
(*
  let* () =
    if
(*
    Hacl.Sign.verify
        ~pk:(Hacl.Sign.unsafe_pk_of_bytes (Bigstring.of_string resolver_public_key))
        ~msg:(Bigstring.of_string body)
        ~signature:(Bigstring.of_string signature)
*)
    Hacl_star.Hacl.Ed25519.verify
      (Bytes.of_string resolver_public_key)
      (Bytes.of_string body)
      (Bytes.of_string signature)
    then Ok ()
    else Error `Certificate_verification_failed
  in
*)
  let resolver_shortterm_public_key = Bytes.sub_string cert 72 32 in
  let client_magic = Bytes.sub_string cert 104 8 in
  let serial = Bytes.get_int32_be cert 112 |> Int32.unsigned_to_int |> Option.get in
  let ts_start = Bytes.get_int32_be cert 116 |> Int32.unsigned_to_int |> Option.get in
  let ts_end = Bytes.get_int32_be cert 120 |> Int32.unsigned_to_int |> Option.get in
  Ok {
    encryption_system;
    resolver_shortterm_public_key;
    client_magic;
    serial;
    ts_start;
    ts_end;
  }

let fetch_and_parse_cert ~rand ~udp address port ~provider_name ~public_key =
  let proto = `Udp in
  let header_id = Bytes.get_uint16_le (rand 2) 0 in
  let header = header_id, Dns.Packet.Flags.singleton `Recursion_desired in
  let provider_domain = Domain_name.of_string_exn provider_name in
  let question = Dns.Packet.Question.create provider_domain Dns.Rr_map.Txt in
  let data = `Query in
  let t = Dns.Packet.create header question data in
  let (buffer, _max_size) = Dns.Packet.encode proto t in
  let dns_query = Cstruct.to_string buffer in

  (* let udp_start = Unix.gettimeofday () in *)
  let response = udp ~timeout:10. address port dns_query in
  (* let udp_end = Unix.gettimeofday () in *)
  (* Printf.eprintf "UDP query took %.01f ms\n%!" ((udp_end -. udp_start) *. 1000.); *)

  match response with
  | Error (`Truncated | `No_connection) as e ->
    e
  | Error `Timeout ->
    Error `Cert_timeout
  | Ok response ->
    match Dns.Packet.decode (Cstruct.of_string response) with
    | Error e ->
      Error (`Bad_dns_response e)
    | Ok dns_response ->
      match dns_response.data with
        | `Answer (answer, _authority) ->
          begin match Dns.Name_rr_map.find provider_domain Dns.Rr_map.Txt answer with
            | None ->
              Error `No_cert
            | Some (_ttl, txts) ->
              let txts =
                Dns.Rr_map.Txt_set.to_seq txts
                |> List.of_seq
                |> List.map (fun cert -> parse_cert (Bytes.of_string cert) public_key)
              in
              Ok txts
          end
        | data ->
          Error (`Non_answer_response data)

let next_multiple_of multiple n =
  let m = n mod multiple in
  if m = 0 then
    n
  else
    n + (multiple - m)

let () = assert (next_multiple_of 4 32 = 32)
let () = assert (next_multiple_of 4 33 = 36)
let () = assert (next_multiple_of 4 34 = 36)
let () = assert (next_multiple_of 4 35 = 36)

let strip_padding buf =
  let rec aux i =
    if i < 0 then Error ()
    else
    match buf.[i] with
    | '\x00' -> aux (i - 1)
    | '\x80' -> Ok i
    | _ -> Error ()
  in
  match aux (String.length buf - 1) with
  | Error _ as e -> e
  | Ok end_ ->
    Ok (String.sub buf 0 end_)

let () = assert (strip_padding "\x80" = Ok "")
let () = assert (strip_padding "abc\x80" = Ok "abc")
let () = assert (strip_padding "abc\x80\x00" = Ok "abc")
let () = assert (strip_padding "abc\x80\x00\x00" = Ok "abc")

let create_padding size =
  assert (size >= 1);
  let pad = Bytes.make size '\x00' in
  Bytes.set_uint8 pad 0 0x80;
  let pad = Bytes.to_string pad in
  pad
(* TODO: quickcheck tests that strip_padding and create_padding are inverting functions *)

type resolve_error = [
  | `Bad_padding
  | `Dns_packet_error of Dns.Packet.err
  | `Invalid_nonce
  | `Invalid_resolver_magic
  | `No_connection
  | `Timeout
  | `Truncated]

let resolve ~rand ~udp ~address ~port cert dns_query =
  let private_key = rand 32 |> Bytes.to_string in
  let public_key = Tweetnacl.crypto_box_create_keypair private_key in
  let module Crypto = (val (
    match cert.encryption_system with
      | `XChacha20Poly1305 -> (module Chacha20_tweetnacl : Crypto)
      | `XSalsa20Poly1305 -> (module Salsa20_tweetnacl : Crypto)
    ))
  in

  let shared_key =
    Crypto.create_shared_key ~private_key ~public_key:cert.resolver_shortterm_public_key
  in

  let nonce = String.concat "" [
      rand 12 |> Bytes.to_string;
      String.make 12 '\x00';
    ]
  in

  let dns_query_pad_length = next_multiple_of 64 (String.length dns_query + 1) in
  let dns_query_pad_length = max 512 dns_query_pad_length in
  let dns_query_pad_length = dns_query_pad_length - String.length dns_query in
  assert (dns_query_pad_length >= 1);
  let dns_query_pad = create_padding dns_query_pad_length in

  let plain_query = String.concat "" [
      dns_query;
      dns_query_pad;
    ]
  in

  assert (String.length shared_key = 32);
  let encrypted_query = Crypto.encrypt ~shared_key ~nonce ~message:plain_query in
  assert (Crypto.decrypt ~cipher:encrypted_query ~nonce ~shared_key = plain_query);
  assert (String.length cert.client_magic = 8);
  let query = String.concat "" [
      cert.client_magic;
      public_key;
      String.sub nonce 0 12;
      encrypted_query;
    ]
  in

  let* response = match udp ~timeout:10. address port query with Ok _ | Error (`No_connection | `Timeout | `Truncated) as x -> x in

  (* angstrom or better error handling *)
  let resolver_magic = String.sub response 0 8 in
  let* () = if resolver_magic = of_hex "7236666e76576a38" then Ok () else Error `Invalid_resolver_magic in

  let server_nonce = String.sub response 8 24 in
  let* () = if String.sub server_nonce 0 12 = String.sub nonce 0 12 then Ok () else Error `Invalid_nonce in

  let cipher = String.sub response 32 (String.length response - 32) in
  let decrypted_response = Crypto.decrypt ~shared_key ~nonce:server_nonce ~cipher in

  match strip_padding decrypted_response with
  | Error () -> Error `Bad_padding
  | Ok decrypted_response ->
    match Dns.Packet.decode (Cstruct.of_string decrypted_response) with
    | Error e ->
      Error (`Dns_packet_error e)
    | Ok dns_response ->
      (match dns_response.data with
        | `Answer (a1, a2) ->
          Printf.printf "answer: %s\n%!" (Fmt.to_to_string Dns.Name_rr_map.pp a1);
          Printf.printf "answer: %s\n%!" (Fmt.to_to_string Dns.Name_rr_map.pp a2);
          ()
        | _ ->
          ()
      );
      Ok dns_response

type error = [resolve_error | fetch_error | cert_error]

let show_error = function
  | `Invalid_prefix -> "Invalid prefix"
  | `Invalid_host host -> (Printf.sprintf "Invalid host: %s" host)
  | `Trailing_garbage -> "Trailing garbage"
  | (`Unknown_stamp_id _) -> "Unknown stamp id"
  | `Base64_error m -> Printf.sprintf "Base64 error (%s)" m
  | `Timeout -> "timeout"
  | `Cert_timeout -> "cert timeout"
  | `Truncated -> "truncated"
  | `No_connection -> "no connection"
  | `Bad_padding -> "bad padding"
  | `Non_answer_response _ -> "non answer response"
  | `No_cert -> "no cert"
  | `Bad_dns_response _ -> "Bad dns"
  | `Dns_packet_error _ -> "dns error"
  | `Invalid_public_key_length -> "invalid public key"
  | `Invalid_resolver_magic -> "invalid resolver magic"
  | `Invalid_nonce -> "invalid nonce"
  | `Bad_magic -> "Bad certficate magic"
  | `Certificate_verification_failed ->"Certificate verification failed"
  | `Invalid_encryption_system_id -> "Invalid encryption system id"
