#!/bin/bash
rm -rf features.csv
touch features.csv
echo "File Name,Family,File Type,CPU Type, Version, Link, Stripped, File Size, Class, Version, OS/ABI, File Type, Machine, Entry Address Point, Start of program headers, Start of section headers, Size of ELF header, Size of program headers, Number of program headers, Size of section headers, Section header string table index, Number of Functions, Size of Functions, Number of Files, Size of Files, Number of Local Functions, Size of Local Functions, Number of Global Functions, Size of Global Functions, Number of Weak Functions, Size of Weak Functions, Number of Hidden Functions, Size of Hidden Functions, Number of Local Objects, Size of Local Objects, Number of Global Objects, Size of Global Objects, Number of Weak Objects, Size of Weak Objects, Number of Hidden Objects, Size of Hidden Objects, Number of Local Files, Size of Local Files, Number of Global Files, Size of Global Files, Number of Weak Files, Size of Weak Files, Number of Hidden Files, Size of Hidden Files,Number of EXECVE,Number of OPEN,Number of CLOSE,Number of READ,Number of WRITE,Number of CONNECT,Number of SOCKET,Number of FORK,Number of CHDIR,Number of CLONE,Number of READONLY,Number of READWRITE,Number of Re-transmissions,Number of Section Headers,Size of text section, Size of data section, Size of rodata section, Size of bss section " > features.csv


topdir='/home/misha/mtp2/IoT_malware_reports'

family_name=`echo "$topdir" | cut -c 3-`
text='final_report.txt'
pcap='output.pcap'


for pathname in "$topdir"/*/"$text" ; do
        project="$(basename "$(dirname "$pathname")")"
	inp_file="$topdir/$project/$text"
	pcap_file="$topdir/$project/$pcap"
	
#------------------------Information from ELF header-------------------------
File_type=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "Filetype") {print $2;next};{}' $inp_file`
file_type=`echo $File_type | cut -d',' -f 1`
cpu_type=`echo $File_type | cut -d',' -f 2`
version_type=`echo $File_type | cut -d',' -f 3`
link_type=`echo $File_type | cut -d',' -f 4`
stripped_type=`echo $File_type | cut -d',' -f 5` # for malicious stripped

File_Size=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "File Size") {print $2;next};{}' $inp_file`
file_size=`echo $File_Size | cut -d'(' -f 2 | cut -d" " -f 1`
class=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Class") {print $2;next};{}' $inp_file`
data=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Data") {print $2;next};{}' $inp_file`
version=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Version") {print $2;next};{}' $inp_file`
os_abi=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  OS/ABI") {print $2;next};{}' $inp_file`
file_type1=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Type") {print $2;next};{}' $inp_file`
machine=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Machine") {print $2;next};{}' $inp_file`
entry_add_point=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Entry point address") {print $2;next};{}' $inp_file`
start_of_program_headers=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Start of program headers") {print $2;next};{}' $inp_file`
start_of_section_headers=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Start of section headers") {print $2;next};{}' $inp_file`

size_of_elf_header=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Size of this header") {print $2;next};{}' $inp_file`
size_of_program_header=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Size of program headers") {print $2;next};{}' $inp_file`
no_of_program_header=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Number of program headers") {print $2;next};{}' $inp_file`
size_of_section_header=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Size of section headers") {print $2;next};{}' $inp_file`
no_of_section_header=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Number of section headers") {print $2;next};{}' $inp_file`
section_header_string_table_index=`awk 'BEGIN{ FS=":";RS="\n" } ($1 == "  Section header string table index") {print $2;next};{}' $inp_file`

#------------------------------------------------------------------------------------#

sed -n '/Section Header Information:/,/Key to Flags:/p' $inp_file > section_header.txt

if [ $no_of_section_header != 0 ] #never us "" for string matching in if condition
then
echo "Section header is not zero"
cat section_header.txt | head -n -1 | tail -n+5 > section_header1.txt

#For malicious elf
text_size_hex=`cat section_header1.txt | tr -s ' ' | sed -n -e 's/^.*] //p' | grep -E '(^|\s).text($|\s)' | cut -d ' ' -f 5`
data_size_hex=`cat section_header1.txt | tr -s ' ' | sed -n -e 's/^.*] //p' | grep -E '(^|\s).data($|\s)' | cut -d ' ' -f 5`
rodata_size_hex=`cat section_header1.txt | tr -s ' ' | sed -n -e 's/^.*] //p' | grep -E '(^|\s).rodata($|\s)' | cut -d ' ' -f 5`
bss_size_hex=`cat section_header1.txt | tr -s ' ' | sed -n -e 's/^.*] //p' | grep -E '(^|\s).bss($|\s)' | cut -d ' ' -f 5`

text_size_dec=$((16#$text_size_hex))

data_size_dec=$((16#$data_size_hex))
rodata_size_dec=$((16#$rodata_size_hex))
bss_size_dec=$((16#$bss_size_hex))

else
echo "initiliasing sections to be zero"
text_size_dec=0
data_size_dec=0
rodata_size_dec=0
bss_size_dec=0
fi

#-------------------------SYMBOL TABLE INFORMATION------------------------------------
sed -n '/Symbol Information:/,/DYNAMIC ANALYSIS RESULTS/p' $inp_file > sym_table.txt
no_of_entries_sym_table=`cat sym_table.txt | head -3 | tail -2 | cut -d" " -f5` 

cat sym_table.txt | head -n -3 | tail -n+5 > sym_table1.txt
no_of_lines=`cat sym_table1.txt | wc -l`

if [ $no_of_lines == $no_of_entries_sym_table ]
then 
	echo "Values match"
else
	echo "Values donot match"
	echo $no_of_entries_sym_table
	no_of_entries_sym_table=0
	#read enter
	
fi  

no_of_functions_sym_table=`cat sym_table1.txt | grep FUNC | wc -l`

if [ $no_of_functions_sym_table == 0 ]
then
size_of_functions_sym_table=0
else
size_of_functions_sym_table=`cat sym_table1.txt | grep FUNC | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_files_sym_table=`cat sym_table1.txt | grep FILE | wc -l`
if [ $no_of_files_sym_table == 0 ]
then
size_of_files_sym_table=0
else
size_of_files_sym_table=`cat sym_table1.txt | grep FILE | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_local_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep LOCAL | wc -l`
if [ $no_of_local_functions_sym_table == 0 ]
then
size_of_local_functions_sym_table=0
else
size_of_local_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep LOCAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_global_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep GLOBAL | wc -l`
if [ $no_of_global_functions_sym_table == 0 ]
then
size_of_global_functions_sym_table=0
else
size_of_global_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep GLOBAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_weak_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep WEAK | wc -l`
if [ $no_of_weak_functions_sym_table == 0 ]
then
size_of_weak_functions_sym_table=0
else
size_of_weak_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep WEAK | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_hidden_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep HIDDEN | wc -l`
if [ $no_of_hidden_functions_sym_table == 0 ]
then
size_of_hidden_functions_sym_table=0
else
size_of_hidden_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep HIDDEN | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_local_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep LOCAL | wc -l`
if [ $no_of_local_objects_sym_table == 0 ]
then
size_of_local_objects_sym_table=0
else
size_of_local_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep LOCAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_global_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep GLOBAL | wc -l`
if [ $no_of_global_objects_sym_table == 0 ]
then
size_of_global_functions_sym_table=0
else
size_of_global_functions_sym_table=`cat sym_table1.txt | grep FUNC | grep GLOBAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_weak_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep WEAK | wc -l`
if [ $no_of_weak_objects_sym_table == 0 ]
then
size_of_weak_objects_sym_table=0
else
size_of_weak_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep WEAK | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_hidden_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep HIDDEN | wc -l`
if [ $no_of_hidden_objects_sym_table == 0 ]
then
size_of_hidden_objects_sym_table=0
else
size_of_hidden_objects_sym_table=`cat sym_table1.txt | grep OBJECT | grep HIDDEN | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_local_files_sym_table=`cat sym_table1.txt | grep FILE | grep LOCAL | wc -l`
if [ $no_of_local_files_sym_table == 0 ]
then
size_of_local_files_sym_table=0
else
size_of_local_files_sym_table=`cat sym_table1.txt | grep FILE | grep LOCAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_global_files_sym_table=`cat sym_table1.txt | grep FILE | grep GLOBAL | wc -l`
if [ $no_of_global_files_sym_table == 0 ]
then
size_of_global_files_sym_table=0
else
size_of_global_files_sym_table=`cat sym_table1.txt | grep FILE | grep GLOBAL | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_weak_files_sym_table=`cat sym_table1.txt | grep FILE | grep WEAK | wc -l`
if [ $no_of_weak_files_sym_table == 0 ]
then
size_of_weak_files_sym_table=0
else
size_of_weak_files_sym_table=`cat sym_table1.txt | grep FILE | grep WEAK | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi

no_of_hidden_files_sym_table=`cat sym_table1.txt | grep FILE | grep HIDDEN | wc -l`
if [ $no_of_hidden_files_sym_table == 0 ]
then
size_of_hidden_files_sym_table=0
else
size_of_hidden_files_sym_table=`cat sym_table1.txt | grep FILE | grep HIDDEN | awk 'BEGIN { FS=" "} { print $3}' | paste -sd+ - | bc`
fi


#--------------------------System calls-----------------------------------------------
sed -n '/CALL TRACE ACTIVITIES/,/NETWORK ACTIVITIES/p' $inp_file > sys_calls.txt
no_of_execve=`cat sys_calls.txt | grep execve | wc -l`
no_of_open=`cat sys_calls.txt | grep open | wc -l`
no_of_close=`cat sys_calls.txt | grep close | wc -l`
no_of_read=`cat sys_calls.txt | grep read | wc -l`
no_of_write=`cat sys_calls.txt | grep write | wc -l`
no_of_connect=`cat sys_calls.txt | grep connect | wc -l`
no_of_socket=`cat sys_calls.txt | grep socket | wc -l`
no_of_fork=`cat sys_calls.txt | grep fork | wc -l`
no_of_chdir=`cat sys_calls.txt | grep chdir | wc -l`
no_of_clone=`cat sys_calls.txt | grep clone | wc -l`
no_of_readonly=`cat sys_calls.txt | grep O_RDONLY | wc -l`
no_of_readwrite=`cat sys_calls.txt | grep O_RDWR | wc -l`

#----------------------retransmissions---------------------
no_of_retransmissions=`tshark -r $pcap_file -Y "tcp.analysis.retransmission" -T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport | wc -l`

#-------------------------FINAL REPORT------------------------------------------------
echo $inp_file,$family_name,$file_type,$cpu_type,$version_type,$link_type,$stripped_type,$file_size,$class,$version,$os_abi,$file_type1,$machine,$entry_add_point,$start_of_program_headers,$start_of_section_headers,$size_of_elf_header,$size_of_program_header,$no_of_program_header,$size_of_section_header,$section_header_string_table_index, $no_of_functions_sym_table, $size_of_functions_sym_table,$no_of_files_sym_table,$size_of_files_sym_table,$no_of_local_functions_sym_table,$size_of_local_functions_sym_table,$no_of_global_functions_sym_table,$size_of_global_functions_sym_table,$no_of_weak_functions_sym_table,$size_of_weak_functions_sym_table,$no_of_hidden_functions_sym_table,$size_of_hidden_functions_sym_table,$no_of_local_objects_sym_table,$size_of_local_objects_sym_table,$no_of_global_objects_sym_table,$size_of_global_functions_sym_table,$no_of_weak_objects_sym_table,$size_of_weak_objects_sym_table,$no_of_hidden_objects_sym_table,$size_of_hidden_objects_sym_table,$no_of_local_files_sym_table,$size_of_local_files_sym_table,$no_of_global_files_sym_table,$size_of_global_files_sym_table,$no_of_weak_files_sym_table,$size_of_weak_files_sym_table,$no_of_hidden_files_sym_table,$size_of_hidden_files_sym_table,$no_of_execve,$no_of_open,$no_of_close,$no_of_read,$no_of_write,$no_of_connect,$no_of_socket,$no_of_fork,$no_of_chdir,$no_of_clone,$no_of_readonly,$no_of_readwrite,$no_of_retransmissions,$no_of_section_header,$text_size_dec,$data_size_dec,$rodata_size_dec,$bss_size_dec >> features.csv

done
