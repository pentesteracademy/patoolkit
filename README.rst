.. image:: https://user-images.githubusercontent.com/743886/43845704-6dbd2558-9ae1-11e8-9f77-239210fe7b6a.png

#########################################################################
PA Toolkit (Pentester Academy Wireshark Toolkit)
#########################################################################

PA Toolkit is a collection of traffic analysis plugins to extend the functionality of Wireshark from a micro-analysis tool and protocol dissector to the macro analyzer and threat hunter. PA Toolkit contains plugins (both dissectors and taps) covering various scenarios for multiple protocols, including:

- WiFi (WiFi network summary, Detecting beacon, deauth floods etc.)
- HTTP (Listing all visited websites, downloaded files)
- HTTPS (Listing all websites opened on HTTPS)
- ARP (MAC-IP table, Detect MAC spoofing and ARP poisoning)
- DNS (Listing DNS servers used and DNS resolution, Detecting DNS Tunnels)

The project is under active development and more plugins will be added in near future.

This material was created while working on "Traffic Analysis: TSHARK Unleashed" course. Those interested can check the course here: https://www.pentesteracademy.com/course?id=42

#############
Terms of Use
#############

- This is licensed under GPL just as Wireshark.

############
Installation
############

Steps:

1. Copy the "plugins" directory to Wireshark plugins directory. 
2. Start wireshark. :) 

One can get the location of wireshark plugins directory by checking `Help > About Wireshark > Folders`

.. image:: https://user-images.githubusercontent.com/743886/43845711-72426d36-9ae1-11e8-9945-0bbe8e078e2a.png

Please opt for **Personal Plugins** directory and NOT the **Global Plugins** directory.

If you prefer **Global Plugins** directory, then please use this branch: https://github.com/pentesteracademy/patoolkit/tree/global-plugins

**Special note for Macbook users:** Paste the plugins in **Personal Lua plugins** and not in **Personal Plugins**.

**Compatibility:** This version is compatible with wireshark version 2.9 and later. For using patoolkit with older version of wireshark please check this branch: https://github.com/pentesteracademy/patoolkit/tree/till-2.8

################
Tool featured at
################

- Blackhat Arsenal 2018 <https://www.blackhat.com/us-18/arsenal/schedule/index.html#pa-toolkit-wireshark-plugins-for-pentesters-12035>
- DEF CON 26 Demolabs <https://defcon.org/html/defcon-26/dc-26-demolabs.html>

##############
Sister Project
##############

VoIPShark (https://github.com/pentesteracademy/voipshark)


#######
Author
#######

- Nishant Sharma, Technical Manager, Pentester Academy <nishant@binarysecuritysolutions.com>
- Jeswin Mathai, Security Researcher, Pentester Academy <jeswin@binarysecuritysolutions.com> 

Under the guidance of Mr. Vivek Ramachandran, CEO, Pentester Academy

##############
Documentation
##############

For more details refer to the "PA-Toolkit.pdf" PDF file. This file contains the slide deck used for presentations.

############
Screenshots
############

PA Toolkit after installation

.. image:: https://user-images.githubusercontent.com/743886/44320933-e4772d80-a3f9-11e8-86c6-82b614221700.png

List of websites visited over HTTP

.. image:: https://user-images.githubusercontent.com/743886/44320940-e8a34b00-a3f9-11e8-98e9-ab003107d15c.png

Search functionality

.. image:: https://user-images.githubusercontent.com/743886/44320950-f48f0d00-a3f9-11e8-897a-d84d5e20e2e0.png

Domain to IP mappings

.. image:: https://user-images.githubusercontent.com/743886/44320953-f8bb2a80-a3f9-11e8-8530-70d36b0a1bff.png

########
License
########

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License v2 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
