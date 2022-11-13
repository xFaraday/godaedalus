package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func prelimcheck(dirforbackups string, dirforconfigs string) bool {
	if os.Getegid() != 0 {
		fmt.Println("You must run this as root")
		return false
	}
	if _, err := os.Stat(dirforbackups); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0700)
		} else {
			return false
		}
	}

	if _, err := os.Stat(dirforconfigs); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0700)
		} else {
			return false
		}
	}

	return true
}

func ssh() {
	fmt.Println("[+] Hardening SSH...")
	chown1 := ("sudo chown root /etc/ssh/ssh_config")
	chown2 := ("sudo chown root /etc/ssh/sshd_config")
	chmod1 := ("sudo chmod 644 /etc/ssh/ssh_config")
	chmod2 := ("sudo chmod 644 /etc/ssh/sshd_config")
	chn1, err := exec.Command("/bin/bash", "-c", chown1).Output()
	if err != nil {
		fmt.Println(err)
		fmt.Println(chn1)
	}
	chn2, err := exec.Command("/bin/bash", "-c", chown2).Output()
	if err != nil {
		fmt.Println(err)
		fmt.Println(chn2)
	}
	ch1, err := exec.Command("/bin/bash", "-c", chmod1).Output()
	if err != nil {
		fmt.Println(err)
		fmt.Println(ch1)
	}
	ch2, err := exec.Command("/bin/bash", "-c", chmod2).Output()
	if err != nil {
		fmt.Println(err)
		fmt.Println(ch2)
	}
}

/*
func telnet() {
	fmt.Println("[+] Configuring Telnet...")

	var (
		telnetPath = "/etc/xinetd.d/telnet"
		telUrl     = "https://raw.githubusercontent.com/CSUSB-CISO/godaedalus/main/Configurations/telnet"
		OldConfig  = "/opt/memento/Configurations/telnet.old"
	)

	//backing up old telnet config
	_, err := os.Stat(telnetPath)
	if err == nil {
		fmt.Println("[+] Backing up old telnet config...")

		bytesRead, err := os.ReadFile(telnetPath)
		if err != nil {
			fmt.Println("[!] Error configuring telnet while reading original telnet path.")
		}

		err = os.WriteFile(OldConfig, []byte(bytesRead), 0644)
		if err != nil {
			fmt.Println("[!] Error configuring telnet while copying old telnet to new path.")
		}

		telRequest, err := http.Get(telUrl)
		if err != nil {
			fmt.Println("[!] Error configuring telnet while grabbing new telnet file from repo.")
		}

		telBody, err := ioutil.ReadAll(telRequest.Body)
		if err != nil {
			fmt.Println("[!] Error configuring telnet while reading http request.")
		}

		file2write := []byte(string(telBody))

		os.WriteFile(telnetPath, []byte(file2write), 0644)
		if err != nil {
			fmt.Println("[!] Error configuring telnet while writing new telnet to file.")
		}
	}
}
*/

func disableCoreDumps() {
	_, err := exec.Command("echo", "'* hard core 0'", ">>", "/etc/security/limits.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("echo", "'* soft core 0'", ">>", "/etc/security/limits.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("echo", "'fs.suid_dumpable=0'", ">>", "/etc/sysctl.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
	// /etc/sysctl.d/9999-disable-core-dump.conf
	_, err = exec.Command("sudo", "sysctl", "-p", "/etc/sysctl.d/99-disable-core-dump.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
}

//func accessRootLogin() {
// access.conf
//	_, err := exec.Command("echo", "+:root:192.168.89.1", ">>", "/etc/security/access.conf").Output()
//	if err != nil {
//		fmt.Println(err)
//	}
//}

//func installPackages() {
//	packageNames := []string{"auditd"}
//	fmt.Println("[+] Installing the following packages: ", packageNames)
//	packageManager := pacmanID()
//	for _, packName := range packageNames {
//		// check package manager, install package according to the package manager available
//		if packageManager == "yum" {
//			// may have to install epel-release before
//			result, _ := exec.Command("bash", "-c", "sudo yum install "+packName+" -y").Output()
//			fmt.Println(string(result))
//		} else if packageManager == "apt" {
//			result, _ := exec.Command("bash", "-c", "sudo apt install "+packName+" -y").Output()
//			fmt.Println(string(result))
//		} else if packageManager == "zypp" {
//			result, _ := exec.Command("bash", "-c", "sudo zypper install "+packName+" -y").Output()
//			fmt.Println(string(result))
//		} else if packageManager == "apk" {
//			result, _ := exec.Command("bash", "-c", "sudo apk add "+packName).Output()
//			fmt.Println(string(result))
//		} else if packageManager == "pacman" {
//			result, _ := exec.Command("bash", "-c", "sudo pacman -S "+packName+" -y").Output()
//			fmt.Println(string(result))
//		} else {
//			fmt.Println("[!] Unknown package manager! Cannot install packages!")
//		}
//	}
//}

//func identifyPackageManager() {
//	supportedPackMan := []string{"apt", "yum", "pacman"}
//	for i := 0; i < len(supportedPackMan); i++ {
//		out, err := exec.Command("which", supportedPackMan[i]).Output()
//		if err != nil {
//			fmt.Println(err)
//		} else {
//			fmt.Println(string(out))
//			//_, err = exec.Command("sudo", supportedPackMan[i], "install", "fail2ban").Output()
//			//_, err = exec.Command("sudo", supportedPackMan[i], "install", "auditd", "audispd-plugins").Output()
//		}
//	}
//}

//func setTcpSynCookies() {
//	_, err := exec.Command("sudo", "echo", "'net.ipv4.tcp_syncookies = 1'", ">>", "/etc/sysctl.conf").Output()
//	if err != nil {
//		fmt.Println(err)
//	}
//	_, err = exec.Command("sudo", "sysctl", "-p").Output()
//	if err != nil {
//		fmt.Println(err)
//	}
//}

func disableIPv6() {
	println("[+] Disabling IPv6...")
	disableFullCmd := "echo net.ipv4.ip_forward = 1 | sudo tee -a /etc/sysctl.conf"
	_, err := exec.Command(disableFullCmd).Output()
	if err != nil {
		fmt.Println(err)
	}
	reloadFullCmd := "sysctl -p"
	_, err = exec.Command(reloadFullCmd).Output()
	if err != nil {
		fmt.Println(err)
	}
}

func disableBlankPassAccts() {
	findCmd := "sudo getent shadow | grep '^[^:]*::' | cut -d: -f1"
	out, err := exec.Command("bash", "-c", findCmd).Output()
	if err != nil {
		fmt.Println(err)
	}
	// iterate through each account w/blank password & disable it
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		disableCmd := "sudo usermod -L " + line
		out, err = exec.Command("bash", "-c", disableCmd).Output()
		if err != nil {
			fmt.Println(err)
		}
	}
}

//func findSUIDSGIDBits() {
//	cmd := "sudo find / -type f \\( -perm -04000 -o -perm -02000 \\)"
//	out, err := exec.Command("bash", "-c", cmd).Output()
//	if err != nil {
//		fmt.Println(err)
//	}
//	fmt.Println(string(out))
//}

//func setLoginAttempts() {
//	fmt.Println("[+] Setting up account lockout. After 3 login unsuccessful login attempts account will be locked for 10 minutes (root included)")
//	lockoutCmd := "sudo echo auth    required           pam_tally2.so onerr=fail deny=3 unlock_time=600 audit even_deny_root root_unlock_time=600 >> /etc/pam.d/common-auth"
//	_, err := exec.Command("bash", "-c", lockoutCmd).Output()
//	if err != nil {
//		fmt.Println("[!] Error encountered while setting up account lockout: ", err)
//	}
//}

func checkFilePermissions() {
	fmt.Println("[+] Checking file permissions...")
	files := []string{"/var/log", "/etc/shadow", "/etc/passwd"}
	varLogCmd := "stat --printf='Permissions for %n are %A' "
	//iterate through each file, print permissions for files
	for _, file := range files {
		perms, err := exec.Command("bash", "-c", varLogCmd+file).Output()
		if err != nil {
			fmt.Println("[!] Error encountered while checking file permissions. Error: ", err)
		}
		fmt.Println(string(perms))
	}
}

func backupSshdConfig(secureLocation string) bool {
	cmd := "cp " + "/etc/ssh/sshd_config" + secureLocation
	_, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println("[!] Error encountered while replacing sshd config file! Error: ", err)
		return false
	}
	return true
}

func sshdConfigReplacement(secureLocation string) {
	fmt.Println("[+] Backing original sshd config file...")
	sshdstatus := backupSshdConfig(secureLocation)
	if !sshdstatus {
		fmt.Println("[!] Error encountered while backing up sshd config file!")
		return
	}
	fmt.Println("[+] Replacing the sshd config file...")
	cmd := "cp " + secureLocation + "/etc/ssh/sshd_config"
	_, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println("[!] Error encountered while replacing sshd config file! Error: ", err)
	}
}

//func disableRSH(filepath string) {
//	ogConfigContent, err := os.ReadFile(filepath)
//	if err != nil {
//		fmt.Println("[!] Error encountered while disabling RSH: ", err)
//	}
//	newConfigFile := strings.Replace(string(ogConfigContent), "    disable = no", "    disable = yes", -1)
//	// Golang will auto overwrite file if it already exists
//	fileHandle, err := os.Create(filepath)
//	if err != nil {
//		fmt.Println("[!] Error encountered while replacing config file for RSH: ", err)
//	}
//	fileHandle.WriteString(string(newConfigFile))
//	fileHandle.Close()
//}

func pacmanID() string {
	packMans := []string{"yum", "zypp", "apk", "apt", "pacman"}
	for _, manager := range packMans {
		// if package manager is installed, it'll return the absolute path to it
		cmd := "which " + manager
		result, _ := exec.Command("bash", "-c", cmd).Output()
		if strings.Contains(string(result), "/") {
			fmt.Println("[+] Package manager identified: " + manager)
			return manager
		}
	}
	return ""
}

func removeInsecureServices() {
	//TODO: differentiate between different package managers
	uninstallCmds := []string{"yum erase xinetd ypserv tftp-server telnet-server rsh-server -y", "sudo apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server -y", "sudo zypper rm xinetd telnetd rsh-server -y", "sudo pacman -Rcns xinetd telnetd rsh-server tftp-server tftpd-hpa -y", "sudo apk del xinetd telnetd rsh-server tftpd-server tftpd-hpa -y"}
	installedPacMan := pacmanID()
	if installedPacMan == "apt" {
		result, _ := exec.Command("bash", "-c", uninstallCmds[1]).Output()
		fmt.Println(string(result))
	} else if installedPacMan == "yum" {
		result, _ := exec.Command("bash", "-c", uninstallCmds[0]).Output()
		fmt.Println(string(result))
	} else if installedPacMan == "zypp" {
		result, _ := exec.Command("bash", "-c", uninstallCmds[2]).Output()
		fmt.Println(string(result))
	} else if installedPacMan == "pacman" {
		result, _ := exec.Command("bash", "-c", uninstallCmds[3]).Output()
		fmt.Println(string(result))
	} else if installedPacMan == "apk" {
		result, _ := exec.Command("bash", "-c", uninstallCmds[4]).Output()
		fmt.Println(string(result))
	} else {
		fmt.Println("[!] Unable to identify package manager on system!")
	}
}

func contains(elements []string, v string) bool {
	for _, s := range elements {
		if v == s {
			return true
		}
	}
	return false
}

func disableSUIDBits() {
	exploitableSUIDs := []string{"ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell", "atomb", "awk", "base32", "base64", "basenc", "basez", "bash", "bridge", "busybox", "bzip2", "capsh", "cat", "chmod", "choom", "chown", "chroot", "cmp", "column", "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "docker", "dosbox", "ed", "efax", "emacs", "env", "eqn", "expand", "expect", "file", "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp", "grep", "gtester", "gzip", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip", "ispell", "jjs", "join", "jq", "jrunscript", "ksh", "ksshell", "kubectl", "ld.so", "less", "logsave", "look", "lua", "make", "mawk", "more", "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv", "nasm", "nawk", "nft", "nice", "nl", "nm", "nmap", "node", "nohup", "od", "openssl", "openvpn", "paste", "perf", "perl", "pg", "php", "pidstat", "pr", "ptx", "python", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts", "rview", "rvim", "sash", "scanmem", "sed", "setarch", "setfacl", "shuf", "soelim", "sort", "sqlite3", "ss", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "tftp", "tic", "time", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "unzip", "update-alternatives", "unndecode", "unnencode", "view", "vigr", "vim", "vimdiff", "vipw", "match", "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash", "zsh", "zsoelim"}
	findSUIDBinariesCmd := "sudo find / -perm /4000"
	suidBinaries, _ := exec.Command("bash", "-c", findSUIDBinariesCmd).Output()
	suidBinariesSlice := strings.Split(string(suidBinaries), "\n")
	for _, binary := range suidBinariesSlice {
		// if the current element we're on is in the list of exploitable suid binaries, we resolve it
		if contains(exploitableSUIDs, binary) {
			_, _ = exec.Command("bash", "-c", "sudo chmod u-s "+binary).Output()
		}
	}
}

func disableSGIDBits() {
	exploitableSGIDs := []string{"ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell", "atomb", "awk", "base32", "base64", "basenc", "basez", "bash", "bridge", "busybox", "bzip2", "capsh", "cat", "chmod", "choom", "chown", "chroot", "cmp", "column", "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "docker", "dosbox", "ed", "efax", "emacs", "env", "eqn", "expand", "expect", "file", "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp", "grep", "gtester", "gzip", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip", "ispell", "jjs", "join", "jq", "jrunscript", "ksh", "ksshell", "kubectl", "ld.so", "less", "logsave", "look", "lua", "make", "mawk", "more", "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv", "nasm", "nawk", "nft", "nice", "nl", "nm", "nmap", "node", "nohup", "od", "openssl", "openvpn", "paste", "perf", "perl", "pg", "php", "pidstat", "pr", "ptx", "python", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts", "rview", "rvim", "sash", "scanmem", "sed", "setarch", "setfacl", "shuf", "soelim", "sort", "sqlite3", "ss", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "tftp", "tic", "time", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "unzip", "update-alternatives", "unndecode", "unnencode", "view", "vigr", "vim", "vimdiff", "vipw", "match", "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash", "zsh", "zsoelim"}
	findSGIDBinariesCmd := "sudo find / -perm /2000"
	sGidBinaries, _ := exec.Command("bash", "-c", findSGIDBinariesCmd).Output()
	sGidBinariesSlice := strings.Split(string(sGidBinaries), "\n")
	for _, binary := range sGidBinariesSlice {
		// if the current element we're on is in the list of exploitable suid binaries, we resolve it
		if contains(exploitableSGIDs, binary) {
			_, _ = exec.Command("bash", "-c", "sudo chmod g-s "+binary).Output()
		}
	}
}

func main() {
	var (
		secureLocation       = "/opt/memento"
		secureLocationConfig = "/opt/memento/Configurations"
	)

	if prelimcheck(secureLocation, secureLocationConfig) {
		fmt.Println("[+] Everything is in order, proceeding with hardening")
	} else {
		fmt.Println("[-] Something went wrong aborting...")
		os.Exit(1)
	}

	//<-------------------------------------->
	//	Sshd config overwrite
	//<-------------------------------------->
	sshdConfigReplacement(secureLocationConfig)
	//<-------------------------------------->
	//	Sshd permission set
	//<-------------------------------------->
	ssh()
	//<-------------------------------------->
	//	Secure permissions on key files
	//<-------------------------------------->
	checkFilePermissions()
	//<-------------------------------------->
	//	Disable accounts with blank passwords
	//<-------------------------------------->
	disableBlankPassAccts()
	//<-------------------------------------->
	//	Disable IPv6
	//<-------------------------------------->
	disableIPv6()
	//<-------------------------------------->
	//	Disable core dumps
	//<-------------------------------------->
	disableCoreDumps()
	//<-------------------------------------->
	//	Disable telnet
	//<-------------------------------------->
	//	Disable rsh
	//<-------------------------------------->
	//	Disable rlogin
	//<-------------------------------------->
	//	Disable rcp
	//<-------------------------------------->
	//	Disable rshd
	//<-------------------------------------->
	//	Disable rlogind
	//<-------------------------------------->
	//	Disable rlogin
	//<-------------------------------------->
	removeInsecureServices()
	//<-------------------------------------->
	//	find GTFObin suid and guid binaries and if so remove the suid and guid bit
	//<-------------------------------------->
	disableSUIDBits()
	disableSGIDBits()
}
