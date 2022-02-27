type sdns =
  | DnsCrypt of { props: int64; addr: string; port: int; public_key: string; provider_name: string }
  | Doh (* unsupported *)
  | DnsOverTls (* unsupported *)
  | DnsCryptRelay (* unsupported *)
  | PlainDns (* unsupported *)
  | Other
val show_sdns : sdns -> string

type parse_sdns_error = [
   | `Base64_error of string
   | `Invalid_host of string
   | `Invalid_prefix
   | `Invalid_public_key_length
   | `Trailing_garbage
   | `Unknown_stamp_id of int]

val parse_sdns : string -> (sdns, parse_sdns_error) result

type cert = {
  encryption_system: [`XSalsa20Poly1305 | `XChacha20Poly1305];
  resolver_shortterm_public_key: string;
  client_magic: string;
  serial: int;
  ts_start: int;
  ts_end: int;
}
val show_cert : cert -> string
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

val fetch_and_parse_cert :
  rand:(int -> bytes) ->
  udp:(timeout:float -> 'addr -> int -> string -> (string, [`No_connection | `Timeout | `Truncated ]) result) ->
  'addr ->
  int ->
  provider_name:string ->
  public_key:string ->
  ((cert, cert_error) result list, fetch_error) result

type resolve_error = [
  | `Bad_padding
  | `Dns_packet_error of Dns.Packet.err
  | `Invalid_nonce
  | `Invalid_resolver_magic
  | `No_connection
  | `Timeout
  | `Truncated]

val resolve :
  rand:(int -> bytes) ->
  udp:(timeout:float -> 'addr -> int -> string -> (string, [< `No_connection | `Timeout | `Truncated ]) result) ->
  address:'addr ->
  port:int ->
  cert ->
  string ->
  (Dns.Packet.t, resolve_error) result

type error = [resolve_error | fetch_error | cert_error]
val show_error : error -> string
