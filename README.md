# AirXDP: An Accelerated and Flexible User-Space Data Plane for WiFi Access Points

Welcome to the AirXDP project!
This XDP based appliation was developed in SIOTLAB at Santa Clara University by
Mridul Gupta and Sujith Polpaya (Ph.D. students) under the guidance of Professor Behnam Dezfouli.

## Overview

The AirXDP application provides a framework for packet processing in the user-space for WiFi Access Points with the help of XDP Sockets.
The implementation aims to provide an efficient and high-performance approach for packet switching from a WiFi interface to an Ethernet interface and vice-versa.

## Features

The **PPE** folder of this repository contains the following main components of AirXDP:

- **PSF**: The primary user-space application that creates the UMEM and XDP sockets for packet switching tasks. 
- **XDP Redirect Program**: The primary kernel space application that transfers packets recieved in the NIC to the PSF.

## Steps

1. Clone the repository and install the necessary submodules:
    ```sh
    git clone --recurse-submodules https://github.com/SIOTLAB/AirXDP.git
    ```
2. Install the necessary dependencies:
    ```sh
    sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386
    ```
3. Navigate to the folder where the submodules are located and run make:
    ```sh
    cd AirXDP/lib
    make
    ```
4. Navigate to the PPE folder and run make:
    ```sh
    cd AirXDP/PPE
    make
    ```
5. Execute the PSF using the following command:
    ```sh
    sudo ./psf -n -s 512000 -t 1536000 -e enp10s0f0np0 -w wls1 -f xdp_redirect_program.o.
    ```
    The options above indicate the following
    - n: Use native attach mode use. The -g option is instead used for generic attach mode.
    - s: The sleep duration in every interaton of the SL stage in &micro;s.
    - t: The maximum timeout value to be used if batch size number of packets are not received in &micro;s.
    - e: The Ethernet interface that will be used for packet switching.
    - w: The WiFi interface that will be used for packet switching.
    - f: The object file of the XDP Rdirect Program 
    
    
## Contacts
Mridul Gupta  magupt@scu.edu
Sujith Popaya spolpaya@scu.edu
Behnam Dezfouli bdezfouli@scu.edu
