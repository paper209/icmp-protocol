## ICMP Protocol
A custom protocol based on ICMP tunneling

## Protocol Structure
* **Common Structure**: `[type (1 byte)]`   
  * type (1 byte): Identifier indicating the role or purpose of the packet.
* **Handshake (Request)**: `[0][size (2 bytes)]`   
  * size (2 bytes): Specifies the total size of the data to be transmitted.
* **Handshake (Reply)**: `[1][max_size (2 bytes)]`   
  * max_size (2 bytes): Indicates the maximum data size that can be received per packet.
* **Data Transmission (Request)**: `[2][data (n bytes)]`   
  * data (n bytes): Contains the payload data.
* **Data Transmission (Reply)**: `[3][size (2 bytes)]`
  * size (2 bytes): Size of the data received.

## Protocol Type
| Value | Operation                  |
|------|-----------------------------|
| 0    | Handshake Request           |
| 1    | Handshake Reply             |
| 2    | Data Transmission Request   |
| 3    | Data Transmission Reply     |
