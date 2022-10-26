Implementation of ECDSA on secp256k1: elliptic curve used in bitcoin

### Instructions

> The code can be run in two modes:

- Debug Mode
  - Command:
    ```
    python main.py
    ```
    Sample Output:
    ```
    test vectors passed
    ```

- Normal Mode
  1) Generate private key:
    ```
    python main.py gen_priv_key --pkf pkfile
    #pkfile = file to store private key
    ```
    
    Sample Output:
    ```
    private key file:  pkfile
    ```
    
  2) Generate public key from private key:
    ```
    python main.py gen_pub_key --pkf pkfile --pubf pubkfile 
    #pkfile = private key file obtained during step 1
    #pubkfile = file to store public key
    ```
    
    Sample Output:
    ```
    public key file:  pubkfile
    ```
    
  3) Sign using private key:
    ```
    python main.py sign --pkf pkfile --inputf data.txt --sigf sigfile 
    #pkfile = private key file obtained during step 1
    #data.txt = file to sign
    #sigfile = file to store signature
    ```
    
    Sample Output:
    ```
    private key file:  pkfile
    file name:  data.txt
    signature file:  sigfile
    ```
    
  4) Verify signature using public key:
    ```
    python main.py verify --pubf pubkfile --inputf data.txt --sigf sigfile 
    #pubkfile = public key file obtained during step 2
    #data.txt = file to verify
    #sigfile = signature file obtained during step 3
    ```
    
    Sample Output:
    ```
    public key file:  pubkfile
    file name:  data.txt
    signature file:  sigfile
    Verify:  True
    ```
