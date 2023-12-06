#from bitstring import BitArray
from sys import argv
import struct
import base64
import sys
import binascii
import subprocess
import io
import os
from datetime import datetime
import xml.etree.ElementTree as ET
#import hexdump
import pkgutil

applicationVersionNumber = "1.0.0"

def calculate_section_crc(section):
    """
    A function that calculates the CRC of a section
    
    Parameters:
    section (string): String of Hex Bytes
    
    Returns:
    int: 32-bit integer of the CRC value
    """

    # Convert section from hex string to bytes
    section_bytes = section # bytes.fromhex(section)
    
    # Initialize the CRC value
    crc = 0xFFFFFFFF

    # CRC-32 polynomial
    polynomial = 0x04C11DB7

    # Calculate the CRC
    for byte in section_bytes:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc <<= 1
                crc ^= (-1 & polynomial)
            else:
                crc <<= 1
    
    # Convert the CRC value to hex string
    crc_hex = hex(crc & 0xFFFFFFFF)[2:].zfill(8).upper()
    #print ("Calculated CRC:", crc_hex)
    return (crc & 0xFFFFFFFF)
    

        
        
        
        

def sendStuffedPacket(output_stream):
    """
    A function to send a stuffed packet to an Output Stream
    
    Parameters:
    output_stream (file): The output stream
    
    Returns:
    null
    """
    stuffed_packet = bytes ([0x47])
    stuffed_packet += b'\x1F\xFF\x10'
    stuffed_packet += b'\xFF' * 184
    output_stream.write (stuffed_packet) 
    
    
    
    
    
    

def extractSCTEInformation(scte35_payload):
    """
    A function to print data about the SCTE35 payload.
    
    Parameters:
    scte35_payload (packet[]): The payload of SCTE35
    
    Returns:
    null
    """
    res = ''.join(format(x, '02x') for x in scte35_payload)
    """
    print("SCTE-35 Hex:", res)
    print("Splice Payload Len:", scte35_payload[3])
    print("Splice Message Len:", scte35_payload[13])
    print("Splice Message Type:", scte35_payload[14])
    print("Splice Event ID:", struct.unpack('>L', scte35_payload[15:19])[0] & 0xFFFFFFFF)
    print("Splice PTS Time:", scte35_payload[21] & 0x01, " ", struct.unpack('>L', scte35_payload[22:26])[0] & 0xFFFFFFFF)
    print("Splice Duration:", (struct.unpack('>L', scte35_payload[27:31])[0] & 0xFFFFFFFF)/90000)                  
    print("Program ID:", (struct.unpack('>H', scte35_payload[31:33])[0] & 0xFFFF))  
    """    
    

    
    
    
    
def buildDSMCCPacket(scte35_payload, version_count, packet, cont_count):
    """
    Function to build a DSMCC Payload from the SCTE Payload
    
    Arguments:
    scte35_payload (packet[]): The payload packets of the SCTE35
    version_count (int): The version of the DSMCC payload
    packet (packet): The SCTE35 packet.
    cont_count (int): The continuity counter.
    
    Returns:
    Byte[]: DSMCC Packet
    """

    #print ("\nBuilding Descriptor with SCTE payload")

    #  Construct Descriptor
    dsm_descriptor = bytes ([
    0x01   ,             # length of header
    0xE1 ,                # RRR/Event type timeline type 0001
    0                 # length of private dats
    ])
    dsm_descriptor += scte35_payload

    #res = ''.join(format(x, '02x') for x in dsm_descriptor)
    #print ("Descriptor Payload:", binascii.hexlify(dsm_descriptor))

    # Base64 encode the SCTE35 payload
    encoded_payload = base64.b64encode(dsm_descriptor) 
    # Print the encoded payload
    #print("Base64 Encoded Payload:", encoded_payload)                            


    #print ("Building DSMCC Section")

    dsmcc_len = 6 + len (encoded_payload) + 4 + 8 + 4                             
    dsmcc_packet = bytes ([0x47])
    dsmcc_packet += packet [1:3]

    byte4 = cont_count | 0x10
    dsmcc_packet += byte4.to_bytes (1, 'big')
    dsmcc_packet += b'\x00\x3D'                 # DSM-CC TID
    dsmcc_siglen = dsmcc_len - 1
    dsmcc_packet += (((dsmcc_siglen & 0x0F00) >> 8) + 0xB0).to_bytes (1, 'big')
    dsmcc_packet += (dsmcc_siglen & 0x00FF).to_bytes (1, 'big')

                            # Length of DSM-CC packet
                            # TID Ext, do-it-now       ETSI TS 102 809 V1.2.1 / Section B32.  TID Ext = EventId 1 (14 bits), Bits 14/15 zero = 0x0001
                            # Version 1 (RR/VVVVV/C)   RR / 5 BIts of Version number / Current/Next indicator (always 1)   Version 1 = 11000011 = C3
                            # section 0
                            # last sec 0
    #version_field = 0xC0 + (version_count << 1) + 0x01  # Build RR/VVVVV/C
    #Mask version count to 5 bits so cycles round.
    version_count = version_count & 0b11111
    version_field = 0xC0 + (version_count << 1 ) + 0x01  # Build RR/VVVVV/C
    dsmcc_packet += b'\x00\x01'
    dsmcc_packet += (version_field & 0x00FF).to_bytes (1, 'big')
    #dsmcc_packet += b'\xC3'
    dsmcc_packet += b'\x00\x00'



    dsmcc_packet += b'\x1a'

    dsmcc_payload_len = len (encoded_payload) + 4
    dsmcc_packet += (dsmcc_payload_len & 0x00FF).to_bytes (1, 'big') 
    dsmcc_packet += b'\x00\x01\xFF\xFF\xFF\xFE\x00\x00\x00\x00'

    dsmcc_packet += encoded_payload# DSM-CC Descriptor - SCTE35 payload

    #print ("DSM-CC Packet:", binascii.hexlify(dsmcc_packet)) 
    #print ("DSM-CC Payload for CRC:", binascii.hexlify(dsmcc_packet [5:dsmcc_len+3]))
    
    dsmcc_crc = calculate_section_crc (dsmcc_packet [5:(dsmcc_len + 3)])                
    dsmcc_packet += dsmcc_crc.to_bytes (4, 'big')
    #dsmcc_packet += b'\xDF\x03\x5D\xFF'

    #print ("DSM-CC Packet with CRC:", binascii.hexlify(dsmcc_packet)) 
    #print ("Len of packet:", len (dsmcc_packet))


    dsmcc_packet += b'\xFF' * (188-len (dsmcc_packet))

    #print ("DSM-CC Packet with padding:", binascii.hexlify(dsmcc_packet)) 
    #print ("Len of packet:", len (dsmcc_packet))
    return(dsmcc_packet)

    

    
    
    
    
    
    
def replace_scte35(input_file, output_file, scte35_pid, replaceNull):
    """
    A function that replaces SCTE35 packets in a Transport Stream with DSMCC ones.
    
    Parameters:
    input_file (String): The name of the file containig the input.
    output_file (String): The name of the file for the output.
    scte35_pid (int): The PID of the SCTE packets.
    replaceNull(boolean): The option to replace null packets
    
    Returns:
    null.
    """
    packetcount=0
    events_replaced=0
    events_notreplaced=0
    version_count=1
    cont_count = 1
    adaptation_len=0
    #print ("Reading Input File :", input_file, "\nWriting Output File:", output_file, "\nSearching for SCTE35 Payload on PID: ", scte35_pid)
    print( "\nSearching for SCTE35 Payload on PID: ", scte35_pid)
    with open(input_file, 'rb') as input_stream, open (output_file, 'wb') as output_stream:
        while True:
            sync_byte = input_stream.read(1)


            if not sync_byte:
                break  # End of file
            if sync_byte != b'\x47':
                #print ("Packet Count :", packetcount, "\nSync Byte :", sync_byte )
                raise ValueError('Invalid sync byte')
            packet = sync_byte + input_stream.read(187)  # Read the entire packet

            # Extract packet PID
            pid = struct.unpack('>H', packet[1:3])[0] & 0x1FFF
            cc =  struct.unpack('>B', packet[3:4])[0] & 0xFF

            # Check if the packet contains SCTE35 payload
            if pid == scte35_pid and packet[3] & 0x10:
                # Extract SCTE35 payload
                if packet [3] & 0x30 == 0x30:
                    adaptation_len = packet [4] + 1
                scte35_length = packet[7+adaptation_len]
                scte35_payload = packet[4+adaptation_len:4+scte35_length+4+adaptation_len]
                if scte35_length != 17:
                    #print("\nSCTE-35 Payload found in packet :", packetcount)
                    #print("SCTE-35 Length :", scte35_length)
                    #Extract SCTE35 information
                    extractSCTEInformation(scte35_payload)
                    #Create DSMCC packet
                    dsmcc_packet = buildDSMCCPacket(scte35_payload, version_count, packet, cont_count)
                    #Update cont_count
                    cont_count += 1
                    cont_count &= 0x0F
                    events_replaced += 1
                    
                    # Write the DSM-CC packet to the output stream
                    
                    """
                    
                    section = '4740CB15003DB0490001C300001A3E0001FFFFFFFE0000000065794A6A623231745957356B496A6F67496E42795A574A315A6D5A6C6369497349434A786369493649475A6862484E6C66513D3D5852E0BCFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
                    dsmcc_packet = bytes.fromhex(section)
                    """
                    #if version_count == 3:
                    #print ("\nWriting replacement packet:", packetcount)
                    output_stream.write(dsmcc_packet)
                    version_count += 1
                #If SCTE is null    
                else:
                    #If replaceNUll is true or false
                    if replaceNull==False:
                        #Not converting null splice into DSM-CC
                        #print ("SCTE Detected, len 17")
                        events_notreplaced +=1
                        #SEND STUFFED PACKET
                        sendStuffedPacket(output_stream)
                    
                    else:
                        #Still converting null splice into DSM-CC
                        #Create DSMCC packet
                        dsmcc_packet = buildDSMCCPacket(scte35_payload, version_count, packet, cont_count)
                        #Update cont_count
                        cont_count += 1
                        cont_count &= 0x0F
                        events_replaced += 1
                    
                    
            else:
                output_stream.write (packet)
            packetcount +=1


        print ("\nTotal SCTE Events Replaced: ", events_replaced)
        print ("Total SCTE Events Ignored: ", events_notreplaced)
        print ("SCTE to DSMCC replacement complete\n")
        #print ("Total Packets Written: ", packetcount)










def find_pmt_pid(pat_data, target_service):
    """
    A function to find the PID of a PMT entry for a specific service.

    Parameters:
    pat_data(list): The list of elements from the PAT.
    target_service(int): The service number to search for.

    Returns:
    pmt_pid(int): The PID of the PMT entry for the target service, or None if not found.
    """
    pmt_pid = None
    looking_for_service = False

    for i, line in enumerate(pat_data):
        if f"Service: {target_service}" in line:
            looking_for_service = True
            # Extract the PID from the previous line (i-1)
            previous_line = pat_data[i - 1]
            if looking_for_service and "PMT" in previous_line:
         
                parts = previous_line.split()
                for j, part in enumerate(parts):
                    if part == "PID:" and j + 1 < len(parts):
                        pid_hex = parts[2]
                        
                        pmt_pid = int(pid_hex, 16)  # Convert hexadecimal to decimal
                        break

    return pmt_pid











def replace_table(input_file, pid, tablexml, output_file):
    """
    Replace tables in the input file with the specified table XML.

    Parameters:
    input_file (str): The input file.
    pid (int): The PID to replace the table.
    tablexml (str): The table XML to inject.
    output_file (str): The output file.

    Returns:
    None
    """
    cmd = [
        'tsp',
        '-I', 'file', input_file,
        '-P', 'inject',
        '-p', str(pid),
        '-r', tablexml,
        '-O', 'file', output_file
    ]
    subprocess.run(cmd, check=True)







def insert_table(input_file, pid, tablexml, reprate_ms, output_file):
    """
    Insert tables in the input file with the specified table XML at regular intervals.

    Parameters:
    input_file (str): The input file.
    pid (int): The PID to insert the table.
    tablexml (str): The table XML to inject.
    reprate_ms (int): The repetition rate in milliseconds.
    output_file (str): The output file.

    Returns:
    None
    """
    cmd = [
        'tsp',
        '-I', 'file', input_file,
        '-P', 'inject',
        '-p', str(pid),
        f'{tablexml}={reprate_ms}',
        '-O', 'file', output_file
    ]
    subprocess.run(cmd, check=True)




def findAvailablePIDs(pmtPID):
    """
    A function to find the best PID for the AIT 
    
    Parameters:
    pmt_pid(string): The hex of the PMT PID
    
    Returns:
    pid(int): The PID to use for the AIT.
    """
    intPID = int(str(pmtPID), 16)
    #Get list of all PIDs
    pids = []

    # Parse the XML file
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    # Find all metadata elements
    metadata_elements = root.findall(".//metadata")

    # Extract PID values and add them to the list
    for metadata_element in metadata_elements:
        pid = metadata_element.attrib.get("PID")
        if pid is not None:
            pid = int(pid.replace(',', ''))
            pids.append(int(pid))
    
    if (intPID+1) in pids:
        # Get nearest PID over 891
        found = false
        i = 891
        while found == false:
            if i in pids:
                i+=1
            else: 
                found = true
                return i
    else:
        return(intPID+1)
        
            
            
       
    

  
  
 
def replaceSCTEElement(xml_file, scte_pid):
    """
    Function to replace a component element in the PMT XML with a specified elementary_PID.
    
    Parameters:
    xml_file (str): The file containing the XML for the PMT.
    scte_pid (str): The hex PID for the component to be replaced.
    """
    
    # Parse the XML file with ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        # Find the specific component element with the given elementary_PID (scte_pid)
        target_component = pmt_element.find(f".//component[@elementary_PID='{scte_pid}']")

        if target_component is not None:
            # Create the new component element structure
            new_component = ET.Element("component", elementary_PID=scte_pid, stream_type="0x0C")
            ET.SubElement(new_component, "stream_identifier_descriptor", component_tag="0x09")
            ET.SubElement(new_component, "data_stream_alignment_descriptor", alignment_type="0x09")

            # Find the index of the target component and insert the new component before it
            target_index = list(pmt_element).index(target_component)
            pmt_element.insert(target_index, new_component)

            # Remove the target component
            pmt_element.remove(target_component)

            # Save the modified XML
            tree.write(xml_file, encoding="utf-8", xml_declaration=True)
        else:
            print(f"Component with elementary_PID '{scte_pid}' not found in the XML.")
    else:
        print("PMT element not found in the XML.")

    
    
    
def addDSMCCToService(xml_file, scte_pid, input_file):
    """
    Function to add a DSMCC element to another PMT
    
    Parameters:
    xml_file (str): The file containing the XML for the PMT.
    scte_pid (str): The pid of the element to add
    """
    getXML(input_file)
    target_component = None
    choice = serviceChoice()
    save_pmt_by_service_id("replacedDSMCCXML.xml", choice[0])
    
    
    # Find the SCTE element
    # Parse the XML file with ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        # Find the specific component element with the given elementary_PID (scte_pid)
        target_component = pmt_element.find(f".//component[@elementary_PID='{scte_pid}']")
    else:
        print("PMT element not found in the XML.")

    
    
    # Insert the target component
    # Parse the XML file with ElementTree
    tree = ET.parse("replacedDSMCCXML.xml")
    root = tree.getroot()

    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        # Create the new component element
        new_component = ET.Element("component", elementary_PID=choice[1], stream_type="0x05")

        # Add the new component to the PMT
        pmt_element.append(target_component)

        # Save the modified XML
        tree.write("replacedDSMCCXML.xml", encoding="utf-8", xml_declaration=True)
        
        
        #Now need to update the TS with the PMT
        intermediateFile = 'tempTS.ts'
        copy_ts_file(input_file, intermediateFile)
        print("Adding DSMCC to Specified PMT")
        replace_table(intermediateFile, choice[1], "replacedDSMCCXML.xml", input_file)
    else:
        print("PMT element not found in the XML.")
    
    
    

def addAITComponentElement(xml_file, pid):
    """
    Function to add a new component element within the existing PMT XML using xml.etree.ElementTree.
    
    Parameters:
    xml_file (str): The file containing the XML for the PMT.
    pid (str): The hex PID for the new component element.
    """
    
    # Parse the XML file with ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        # Create the new component element
        new_component = ET.Element("component", elementary_PID=pid, stream_type="0x05")

        # Create child elements for the new component
        ET.SubElement(new_component, "stream_identifier_descriptor", component_tag="0xAA")
        ET.SubElement(new_component, "application_signalling_descriptor")

        # Add the new component to the PMT
        pmt_element.append(new_component)

        # Save the modified XML
        tree.write(xml_file, encoding="utf-8", xml_declaration=True)
    else:
        print("PMT element not found in the XML.")
    
 
 



def process_ts_file(input_file, output_file, processNumber, pmt_pid):
    """
    Function to process the input stream and send to an output stream
    
    Parameters:
    input_file(String): The input file
    output_file(String): The output file
    processNumber(String): The number of the process
    pmt_pid(string): The Hex PMT PID.
    
    Returns:
    null
    """
    #Make PMT XML for the channel
    save_pmt_by_service_id("pmtXML.xml", processNumber)
    
    print("\nSelect Process: ")
    print("0: Replace SCTE-35 with DSM-CC")
    print("1: Insert AIT")
    print("2: Replace SCTE-35 with DSM-CC and Insert AIT")
    choice = int(input("Enter index of process choice: "))
    
    #IF BOTH
    if choice == 2:
        # Replace SCTE35 packets with DSMCC 
        # Find SCTE Pid
        scte_pid = getSCTEPID()
        if scte_pid is not None:
            int_scte_pid = int(str(scte_pid), 16)
        else:
            print("SCTE PID not found, run on service with SCTE")
            sys.exit(0)
        # Choice to replace null or not
        print("\nReplace Null SCTE?: ")
        print("0: No")
        print("1: Yes")
        nullChoice = int(input("Enter index of choice: "))
        
        if nullChoice == 1:
            replace_scte35(input_file, "intermediate.ts", int_scte_pid, True)
        else:
            replace_scte35(input_file, "intermediate.ts", int_scte_pid, False)
            
        # Replace the SCTE Elements with DSMCC ones
        print(f"Replacing SCTE Element with DSMCC in PMT")
        replaceSCTEElement("pmtXML.xml", scte_pid)
         
            
        
        #insert rate
        insertRate = (input("\nAIT Insert Rate (default is 1000): ")) 
        if not insertRate:
            insertRate = 1000
        #find available PIDs
        aitPID = findAvailablePIDs(int(pmt_pid,16))
        hex_aitPID = '0x{:04x}'.format(aitPID)
        
        #Insert AIT Table
        
        print("\nChoose AIT Insertion Method: ")
        print("0: From XML")
        print("1: Manual")
        choice2 = int(input("Enter index of AIT choice: "))
        
        if choice2 == 0:
            aitXML = (input("\nXML File Name: "))
            if not(aitXML.endswith('.xml')):
                aitXML = aitXML+".xml"
            print(f"Adding AIT Element to PMT")
            insert_table('intermediate.ts', aitPID, aitXML, insertRate, 'intermediate-b.ts')
        else:
            #Input data
            applicationID = (input("\nEnter Application ID: "))
            organizationID = (input("Enter Organization ID: "))
            url = (input("Enter URL: "))
            applicationProfile = (input("Enter Profile (default is 0x0000): ")) 
            if not applicationProfile:
                applicationProfile = "0x0000"
            applicationVersion = (input("Enter Application Version: "))
            applicationName = (input("Enter Application Name: "))
            initialPath = (input("Enter Initial Path (default is index.html): "))
            if not initialPath:
                initialPath = "index.html"
            
            #CreateFile
            createAITXML(applicationID, organizationID, url, applicationProfile, applicationVersion, applicationName, initialPath)
            
            print(f"\nAdding AIT Element to PMT")
            insert_table('intermediate.ts', aitPID, 'aitXML.xml', insertRate, 'intermediate-b.ts')
        
       
        #Make new PMT
        
        
        
        #Add the AIT to the pmt
        addAITComponentElement("pmtXML.xml", hex_aitPID)
        
        # PMT NEEDS TO ALTER AND INSERT
        print(f"Replacing old PMT with new PMT")
        replace_table("intermediate-b.ts", pmt_pid, 'pmtXML.xml', output_file)
        
        replaceChoice = True
        while replaceChoice == True:
            #adding the DSMCC Element to another service
            print("\nAdd DSMCC Element to another service?: ")
            print("0: No")
            print("1: Yes")
            dsmccChoice = int(input("Enter index of choice: "))
            #if yes, add function
            if dsmccChoice == 1:
                addDSMCCToService("pmtXML.xml", scte_pid, output_file)
            else:
                replaceChoice = False   
        
        
        
        
    #If just SCTE    
    elif choice == 0:
        # Replace SCTE35 packets with DSMCC 
        # Find SCTE Pid
        scte_pid = getSCTEPID()
        if scte_pid is not None:
            int_scte_pid = int(str(scte_pid), 16)
        else:
            print("SCTE PID not found, run on service with SCTE")
            sys.exit(0)
        
        # Choice to replace null or not
        print("\nReplace Null SCTE?: ")
        print("0: No")
        print("1: Yes")
        nullChoice = int(input("Enter index of choice: "))
        
 
        if nullChoice == 1:
            replace_scte35(input_file, "intermediate.ts", int_scte_pid, True)
        else:
            replace_scte35(input_file, "intermediate.ts", int_scte_pid, False)
            
        # Make new PMT and insert
        
        
        # Replace the SCTE Elements with DSMCC ones
        print(f"Replacing SCTE Element with DSMCC in PMT")
        replaceSCTEElement("pmtXML.xml", scte_pid)
        
        print(f"Replacing old PMT with new PMT")
        replace_table("intermediate.ts", pmt_pid, 'pmtXML.xml', output_file)
        
        replaceChoice = True
        while replaceChoice == True:
            #adding the DSMCC Element to another service
            print("\nAdd DSMCC Element to another service?: ")
            print("0: No")
            print("1: Yes")
            dsmccChoice = int(input("Enter index of choice: "))
            #if yes, add function
            if dsmccChoice == 1:
                addDSMCCToService("pmtXML.xml", scte_pid, output_file)
            else:
                replaceChoice = False
        
       


    #If just AIT
    else:
        #Insert AIT Table
        #insert rate
        insertRate = (input("\nAIT Insert Rate (default is 1000): ")) 
        if not insertRate:
            insertRate = 1000
        #find available PIDs
        aitPID = findAvailablePIDs(int(pmt_pid,16))
        hex_aitPID = hex_aitPID = '0x{:04x}'.format(aitPID)
        #Insert AIT Table
        
        print("\nChoose AIT Insertion Method: ")
        print("0: From XML")
        print("1: Manual")
        choice2 = int(input("Enter index of AIT choice: "))
        
        if choice2 == 0:
            aitXML = (input("\nXML File Name: "))
            if not(aitXML.endswith('.xml')):
                aitXML = aitXML+".xml"
            print(f"Adding AIT Element to PMT")
            insert_table(input_file, aitPID, aitXML, insertRate, 'intermediate.ts')
        else:
            #Input data
            applicationID = (input("\nEnter Application ID: "))
            organizationID = (input("Enter Organization ID: "))
            url = (input("Enter URL: "))
            applicationProfile = (input("Enter Profile (default is 0x0000): ")) 
            if not applicationProfile:
                applicationProfile = "0x0000"
            applicationVersion = (input("Enter Application Version: "))
            applicationName = (input("Enter Application Name: "))
            initialPath = (input("Enter Initial Path (default is index.html): "))
            if not initialPath:
                initialPath = "index.html"
            
            #CreateFile
            createAITXML(applicationID, organizationID, url, applicationProfile, applicationVersion, applicationName, initialPath)
            
            print(f"\nAdding AIT Element to PMT")
            insert_table(input_file, aitPID, 'aitXML.xml', insertRate, 'intermediate.ts')
        
        
        
        # Insert AIT element
        addAITComponentElement("pmtXML.xml", hex_aitPID)
        
        # PMT NEEDS TO ALTER AND INSERT
        print(f"Replacing old PMT with new PMT")
        replace_table("intermediate.ts", pmt_pid, 'pmtXML.xml', output_file)


    #Delete intermediate files
    """
    os.remove("intermediate.ts")
    os.remove("intermediate-b.ts")
    """



def createAITXML(applicationID, organizationID, url, applicationProfile, applicationVersion, applicationName, initialPath):
    # Create the root element
    root = ET.Element("tsduck")

    # Create the AIT element with attributes
    ait = ET.SubElement(root, "AIT")
    ait.set("application_type", "0x0010")
    ait.set("current", "true")
    ait.set("test_application_flag", "false")
    ait.set("version", "1")
    
    
    

    # Create the application element
    application = ET.SubElement(ait, "application")
    application.set("control_code", "0x01")

    # Create the application_identifier element
    app_identifier = ET.SubElement(application, "application_identifier")
    app_identifier.set("application_id", f"{applicationID}")
    app_identifier.set("organization_id", f"{organizationID}")
    

    # Create the transport_protocol_descriptor element
    tp_descriptor = ET.SubElement(application, "transport_protocol_descriptor")
    tp_descriptor.set("transport_protocol_label", "0x01")

    # Create the http element
    http = ET.SubElement(tp_descriptor, "http")

    # Create the url element with the 'base' attribute
    url_element = ET.Element("url", base=url)

    # Append the url element to the http element
    http.append(url_element)

    # Create the application_descriptor element
    app_descriptor = ET.SubElement(application, "application_descriptor")
    app_descriptor.set("application_priority", "1")
    app_descriptor.set("service_bound", "true")
    app_descriptor.set("visibility", "3")
    
    

    # Create the profile element
    profile = ET.SubElement(app_descriptor, "profile")
    profile.set("application_profile", f"{applicationProfile}")
    profile.set("version", f"{applicationVersion}")
    
    

    # Create the transport_protocol element
    transport_protocol = ET.SubElement(app_descriptor, "transport_protocol")
    transport_protocol.set("label", "0x01")

    # Create the application_name_descriptor element
    app_name_descriptor = ET.SubElement(application, "application_name_descriptor")

    # Create the language element
    language = ET.SubElement(app_name_descriptor, "language")
    language.set("application_name", f"{applicationName}")
    language.set("code", "eng")
    

    # Create the simple_application_location_descriptor element
    location_descriptor = ET.SubElement(application, "simple_application_location_descriptor")
    location_descriptor.set("initial_path", f"{initialPath}")

    # Create an ElementTree object with the root element
    tree = ET.ElementTree(root)

    # Save the XML to a file
    tree.write("aitXML.xml")











def getSCTEPID():
    """
    A function to get the SCTE PID from the PMT
    
    Parameters:
    None
    
    Returns:
    scte_pid(String): The SCTE PID
    """
    tree = ET.parse("pmtXML.xml")
    root = tree.getroot()

    # Find the PMT tag
    pmt_tag = root.find(".//PMT")

    if pmt_tag is not None:
        # Find the component with the specified stream type
        component_tag = pmt_tag.find(f"./component[@stream_type='0x86']")

        if component_tag is not None:
            # Extract the elementary PID from the component
            elementary_pid = component_tag.attrib.get("elementary_PID")
            return elementary_pid

    return None







                
                        
                
                
def getXML(input_file):
    """
    A function to get the XML given a PID
    
    Parameters:
    input_file(String): The input file
    
    Returns:
    null
 
    """

    command = ['tsp', '-I', 'file', input_file, '-P', 'psi', '-x', "dataXML.xml", '-d']
       
       
      
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        # Check for errors
        if process.returncode != 0:
            print(f"Error executing TSDuck command: {error.decode()}")
        else:
            with open(output_file, 'wb') as binary_output:
                binary_output.write(output)
      
           
    except Exception as e:
        print(f"An error occurred: {e}")
        
     





def get_service_name(target_service_id):
    """
    Function to get the service name based on the service number
    
    Parametes:
    target_service_id(String): The service ID
    
    Returns:
    service_name(String): The name of the service
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    for sdt in root.iter('SDT'):
        for service in sdt.iter('service'):
            service_id = service.attrib.get('service_id')

            if service_id == target_service_id:
                service_name = None
                for descriptor in service.iter('service_descriptor'):
                    service_name = descriptor.attrib.get('service_name')

                return service_name

    return None






def save_pmt_by_service_id(xml_file, service_id):
    """
    Save the PMT tag with the provided service ID to the same XML file.

    Parameters:
    xml_file (str): The path to the XML file.
    service_id (str): The service ID to search for.

    Returns:
    None
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    matching_pmts = []

    # Iterate through PMT tags and find the one with the matching service ID
    for pmt in root.findall(".//PMT"):
        if pmt.attrib.get("service_id") == service_id:
            matching_pmts.append(pmt)

    # Create a new XML tree with the matching PMT tags
    new_root = ET.Element("tsduck")
    new_root.extend(matching_pmts)
    new_tree = ET.ElementTree(new_root)

    # Save the new XML tree to the original XML file
    with open(xml_file, 'wb') as output_file:
        new_tree.write(output_file, encoding="utf-8", xml_declaration=True)



def save_pat():
    """
    Save the PAT tag to the same XML file.

    Parameters:
    None

    Returns:
    None
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    matching_pats = []

    # Iterate through PMT tags and find the one with the matching service ID
    for pat in root.findall(".//PAT"):
        matching_pats.append(pat)

    # Create a new XML tree with the matching PMT tags
    new_root = ET.Element("tsduck")
    new_root.extend(matching_pats)
    new_tree = ET.ElementTree(new_root)

    # Save the new XML tree to the original XML file
    with open("patXML.xml", 'wb') as output_file:
        new_tree.write(output_file, encoding="utf-8", xml_declaration=True)







     
      
            

def serviceChoice():
    tree = ET.parse("patXML.xml")
    root = tree.getroot()
    servicesList = []

    pat_info = root.find(".//PAT")
    if pat_info is not None:
        services = pat_info.findall(".//service")

        for index, service in enumerate(services):
            service_id = service.get("service_id")
            program_map_pid = service.get("program_map_PID")
            serviceName = get_service_name(service_id)
            servicesList.append([service_id, program_map_pid, serviceName])
            print(f"Index: {index}, Service ID: {service_id}, Program Map PID: {program_map_pid}, Service Name: {serviceName}")
            
        # Choose the service        
        choice = int(input("Enter the index of the service: "))
        if(choice>=0 and choice < len(services)):
            serviceChoice = servicesList[choice][0]
            pmtChoice = servicesList[choice][1]
            serviceName = servicesList[choice][2]
            return([serviceChoice, pmtChoice, serviceName])






def processMultiple(input_file, output_file):
    """
    Function to process all of the service choices
    
    Parameters:
    input_file(String): The input file
    output_file(String): The output file
    
    Returns:
    None
    """
    #Get the relevant XMLs for the file
    getXML(input_file)
    save_pat()
    
    #Get data about service chosen
    choices = serviceChoice()
    service = choices[0]
    pmtPID = choices[1]
   
    #save_pmt_by_service_id("pmtXML.xml", service)
    process_ts_file(input_file, output_file, service, pmtPID)
    print("\n\nAnother Channel? ")
    print("0: No")
    print("1: Yes")
    more = int(input("Enter index of choice: "))
    if(more == 1):
        getXML(output_file)
        save_pat()
        #Copy current output file to temp
        tempFile = "tempTS.ts"
        copy_ts_file(output_file, tempFile)
        #Process temp file to output.
        processMultiple(tempFile, output_file)
    
    
   

def copy_ts_file(source_file, destination_file):
    """
    A function to copy the contents of a TS file to another
    
    Parameters:
    source_file(String): The file to be copied
    destination_file(String): The file to be copied to
    
    Returns:
    None
    """
    try:
        with open(source_file, 'rb') as source, open(destination_file, 'wb') as destination:
            # Read and copy the contents of the source TS file
            while True:
                chunk = source.read(4096)  # Read in chunks
                if not chunk:
                    break
                destination.write(chunk)  # Write the chunk to the destination TS file
        #print(f"Contents from '{source_file}' copied to '{destination_file}' successfully.")
    except FileNotFoundError:
        print("File not found error.")
    except Exception as e:
        print(f"An error occurred: {e}")


        
      

def check_tsduck_version():
    """
    A function to check the TS Duck version on the path
    
    Parameters:
    None
    
    Returns:
    None
    """
    try:
        # Run the 'tsversion' command and capture the output
        result = subprocess.run(['tsversion'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()
        #print(result)

        # Check if the first line contains a number
        if output_lines and output_lines[0].strip().isdigit():
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        # If the 'tsversion' command fails or isn't found, return False
        print(f"Error: {e}")
        return False

    
        


    
if __name__ == "__main__":

    
    datetime = datetime.now()
    time = datetime.strftime("%Y%m%d%H%M%S")
    
    input_file = argv[1]
    if not(input_file.endswith(".ts")):
        input_file = input_file + ".ts"
    output_file = argv[1]+(f"_Processed_{time}.ts")
    
    print(f"Alter Stream Version: {applicationVersionNumber}\n")
    #Check for TS Duck
    if not(check_tsduck_version):
       print("TSDuck is required in the path for this application to work. \nDownload at https://tsduck.io/download/tsduck/") 
       sys.exit(0)
    else: 
        processMultiple(input_file, output_file)
    
    
    """
    choices = serviceChoice()
    service = choices[0]
    pmtPID = choices[1]
   
    save_pmt_by_service_id(service)
    process_ts_file(input_file, output_file, service, pmtPID)
    """
    

    
    
    """
    Take file name make input and output files
    get the XML of the PAT and store in patXML.xml
    choose service from patXML.xml
    store xml of PSI in data.xml
    get PMT for specific service by trimming data.xml and store in pmtXML.xml
    data.xml used again to get available pids.
    """
    
    
    
   

