*****   This is part of the fork of Mitsubishi Electric Automotive VissV2 implementation

GT client, as its name refers "Grand Touring" is an implementation of a real and user friendly client example.

It can make petitions to AGT, AT and Viss Server. All of this petitions will be via HTTP Request.

The client implements a menu that will have several options.

# main
## Client initialization
### RSA KeyPair Generation
### Print RSA KeyPair in Screen
### Export RSA KeyPair to File
### Import RSA KeyPair from File
## AGT Communication
### Post Request to AGT
#### Not using RSA authentication
#### Using RSA authentication 
### Claim initialization
#### Default claims
#### New/change claim
#### Delete claim
#### Show AG token received
#### Generate AG token for a friend (only if LT AGT)  
## at communication
### Ask for AT using AGT received
#### Show Access token received
## Vissv2 Server communication 
### HTTP request
#### get
#### post
### WebSocket request
#### get
#### post
#### subscribe (in new window)

main
├── Client initialization
│   ├── Generates keys (if it has to)
│   └── Ask for log generation
├── agt communication
│   └── Ask for AG token.
│       ├── Show AG token received
│       └── Generate AG token for a friend (only if LT AGT)
├── at communication
│   └── Ask for AT using AGT received
│       └── Show Access token received
└── Vissv2 Server communication
    ├── HTTP request
    │   ├── get
    │   └── post
    └── WebSocket request
        ├── get
        ├── post
        └── subscribe (in new window)