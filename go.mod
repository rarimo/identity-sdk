module github.com/rarimovoting/identity

go 1.22

toolchain go1.22.2

require (
	github.com/ethereum/go-ethereum v1.13.14
	github.com/iden3/go-circuits/v2 v2.0.1
	github.com/iden3/go-iden3-core/v2 v2.0.4
	github.com/iden3/go-iden3-crypto v0.0.16
	github.com/iden3/go-rapidsnark/types v0.0.3
	github.com/rarimo/go-jwz v1.0.3
	github.com/rarimo/go-merkletree v1.0.1
	github.com/rarimo/go-schema-processor v1.0.2
	github.com/rarimo/registration-relayer v0.1.2
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/crypto v0.19.0
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.12.1 // indirect
	github.com/crate-crypto/go-kzg-4844 v0.7.0 // indirect
	github.com/deckarep/golang-set/v2 v2.1.0 // indirect
	github.com/ethereum/c-kzg-4844 v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/supranational/blst v0.3.11 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	gitlab.com/distributed_lab/logan v3.8.1+incompatible // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/tools v0.21.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

require (
	// github.com/btcsuite/btcd v0.0.0-20171128150713-2e60448ffcc6 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.2.4 // indirect
	github.com/iden3/go-merkletree-sql/v2 v2.0.6 // indirect
	github.com/iden3/go-rapidsnark/verifier v0.0.5 // indirect
	github.com/iden3/go-rapidsnark/witness/v2 v2.0.0 // indirect
	github.com/iden3/go-rapidsnark/witness/wazero v0.0.0-20230524142950-0986cf057d4e // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/tetratelabs/wazero v1.6.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/btcsuite/btcd v0.0.0-20171128150713-2e60448ffcc6 => github.com/btcsuite/btcd v0.24.0
