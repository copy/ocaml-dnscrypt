let _server =
  "sdns://AQIAAAAAAAAADTIwOS41OC4xNDcuMzYgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz"
  |> Dnscrypt.parse_sdns
  |> function
  | Ok DnsCrypt { addr; port; public_key; provider_name; props = _ }->
    (addr, port, public_key, provider_name)
  | _ ->
    failwith "Not a dnscrypt server"
(* let server = ("5.1.66.255", 8443, "\007\208z\241\207\220]\153v\157?\002f\144\167\004Ie\194t'ly\028\174\245\174\243\185\012F\250", "2.dnscrypt-cert.ffmuc.net") *)
let server = ("9.9.9.10", 8443, "g\200G\184\200u\140\209 $UC\190ugF\2234\223\029\132\192\011\140G\003h\223\130\029\134>", "2.dnscrypt-cert.quad9.net")
(* let server = ("77.88.8.78", 15353, "\211\132\192q\201\247Fb\175*\204\213{]\204\151\020\212\007\182\1736\001\225\174\220\006\213mIc'", "2.dnscrypt-cert.browser.yandex.net") *)
(* let server = ("162.221.207.228", 443, "13r\173YV2\194Ak\135/\t\143\133\027\221\185e(Ll\190\154O\025\td0\219\169Z", "2.dnscrypt-cert.cryptostorm.is") *)
(* let server = ("23.19.67.116", 443, "13r\173YV2\194Ak\135/\t\143\133\027\221\185e(Ll\190\154O\025\td0\219\169Z", "2.dnscrypt-cert.cryptostorm.is") *)
(* let server = ("64.42.181.227", 443, "13r\173YV2\194Ak\135/\t\143\133\027\221\185e(Ll\190\154O\025\td0\219\169Z", "2.dnscrypt-cert.cryptostorm.is") *)

let rand length =
  let f = Unix.openfile "/dev/urandom" [] 0 in
  let buffer = Bytes.create length in
  let bytes_read = Unix.read f buffer 0 length in
  assert (bytes_read = length);
  Unix.close f;
  buffer

let udp ?timeout ?(response_buffer_size=64*1024) addr port packet =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let addr = Unix.ADDR_INET (addr, port) in
  match Unix.sendto_substring socket packet 0 (String.length packet) [] addr with
  | exception Unix.Unix_error (Unix.ENETUNREACH, _, _) ->
    Error `No_connection
  | _written ->
  let buffer = Bytes.create response_buffer_size in
  Option.iter (fun timeout -> Unix.setsockopt_float socket Unix.SO_RCVTIMEO timeout) timeout;
  match Unix.recv socket buffer 0 (Bytes.length buffer) [] with
  | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) ->
    (* These errors can also happen if the socket is marked as non-blocking; if
       we ever mark the socket non-blocking we will need to distinguish here *)
    Error `Timeout
  | read ->
    (* doesn't distinguish between an exact buffer-sized read and one larger.
       Unfortunately, that seems to be impossible *)
    if read >= response_buffer_size then
      Error `Truncated
    else
      Ok (Bytes.sub_string buffer 0 read)
let udp = udp ~timeout:10. ?response_buffer_size:None

let main host_to_resolve dns_type =
  let server_address, server_port, public_key, provider_name = server in
  Printf.eprintf "Server: (%S, %d, %S, %S)\n%!" server_address server_port public_key provider_name;
  let server_address = Unix.inet_addr_of_string server_address in
  match Dnscrypt.fetch_and_parse_cert ~rand ~udp server_address server_port ~provider_name ~public_key with
  | Error `Cert_timeout ->
    prerr_endline "Failed to fetch cert (timeout)"
  | Error _ ->
    prerr_endline "Failed to fetch cert"
  | Ok certs ->
    List.iteri (fun i cert ->
        match cert with
        | Error e ->
          Printf.eprintf "Cert %d: %s\n%!" i (Dnscrypt.show_error (e :> Dnscrypt.error))
        | Ok cert ->
          Printf.eprintf "Cert %d: %s\n%!" i @@ Dnscrypt.show_cert cert
      ) certs;
    let certs = List.filter_map Result.to_option certs
    in
    (* mirage-crypto only supports chacha *)
    (* let certs = List.filter (fun cert -> cert.Dnscrypt.encryption_system = `XChacha20Poly1305) certs in *)
    match certs with
    | [] ->
      prerr_endline "No valid cert from server"
    | cert :: _ ->
      let dns_query =
        let proto = `Udp in
        let header_id = Bytes.get_uint16_le (rand 2) 0 in
        let header = header_id, Dns.Packet.Flags.singleton `Recursion_desired in
        let question = Domain_name.of_string_exn host_to_resolve, dns_type in
        let data = `Query in
        let t = Dns.Packet.create header question data in
        let (buffer, _max_size) = Dns.Packet.encode proto t in
        Cstruct.to_string buffer
      in
      match Dnscrypt.resolve ~rand ~udp ~address:server_address ~port:server_port cert dns_query with
      | Error e ->
        Printf.eprintf "Error: %s\n%!" (Dnscrypt.show_error (e :> Dnscrypt.error))
      | Ok dns_response ->
        print_endline @@ Fmt.to_to_string Dns.Packet.pp dns_response

let () =
  Printexc.record_backtrace true;
  match Sys.argv |> Array.to_list |> List.tl with
  | [host] | [host; "a"] ->
    main host (`K (Dns.Rr_map.K Dns.Rr_map.A))
  | [host; "aaaa"] ->
    main host (`K (Dns.Rr_map.K Dns.Rr_map.Aaaa))
  | [host; "cname"] ->
    main host (`K (Dns.Rr_map.K Dns.Rr_map.Cname))
  | [host; "any"] ->
    main host `Any
  | _ ->
    prerr_endline "Usage: dig host [a|aaaa|cname|any]";
    exit 1
