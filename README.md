# mini-dns

A lightweight DNS server implementation in Rust. It's designed to parse a zone file for DNS records and respond to `A` and `CNAME` queries.

## How to run it in production

### 1. Configure the zone file

The server loads DNS records from a zone file. The path to the zone file is hardcoded in `src/main.rs`. By default, it points to `zones/example.zone`. You can modify this path to point to your own zone file.

The zone file should have the following format, with each record on a new line:

```
<domain> <ttl> <type> <data>
```

For example:

```
example.com. 3600 A 192.0.2.1
www.example.com. 3600 CNAME example.com.
```

### 2. Build the project

Build the project in release mode:

```bash
cargo build --release
```

### 3. Run the server

Once built, you can run the server using the following command:

```bash
./target/release/mini-dns
```

The server will start and listen on `127.0.0.1:8888` for DNS queries.