package main

import (
	"fmt"
	"os"
)

func prelimcheck() bool {
	if os.Getegid() != 0 {
		fmt.Println("You must run this as root")
		return false
		os.Exit(1)
	}
	return true
}

func main() {
	if prelimcheck() {
		fmt.Println("You are root, lets do some hardening!")
	}
	/*
		Look into namespace.conf to see if polyinstantiation is a good security move
		https://www.cyberciti.biz/faq/linux-namespaces-linux-kernel-virtualization/

		Install and configure fail2ban
		https://www.cyberciti.biz/faq/how-to-install-fail2ban-on-linux/

		GAIN NETWORK CONTROL set firewall rules
		https://www.cyberciti.biz/faq/linux-firewall-firewall-rules-linux-firewall-commands/

		check permissions for /etc/passwd && /etc/shadow
		https://www.cyberciti.biz/faq/linux-check-file-permissions-linux-command/

		find GTFObin suid and guid binaries and if so remove the suid and guid bit
		https://www.cyberciti.biz/faq/linux-find-suid-and-guid-files-linux-command/

		check permissions for /var/log
		https://www.cyberciti.biz/faq/linux-check-file-permissions-linux-command/



		Disable wack http methods for apache
		https://www.cyberciti.biz/faq/linux-apache-disable-http-methods-apache-command/

		For SSH stuff:
		check permissions for /etc/ssh/ stuff
		https://dev-sec.io/baselines/ssh/

		import baseline secure sshd config file and overwrite sshd_config file in place

		Disable telnet
		https://www.cyberciti.biz/faq/linux-disable-telnet-telnet-server-linux-command/

		Disable rsh
		https://www.cyberciti.biz/faq/linux-disable-rsh-rsh-server-linux-command/

		Disable rlogin
		https://www.cyberciti.biz/faq/linux-disable-rlogin-rlogin-server-linux-command/

		Disable rcp
		https://www.cyberciti.biz/faq/linux-disable-rcp-rcp-server-linux-command/

		Disable rshd
		https://www.cyberciti.biz/faq/linux-disable-rshd-rshd-server-linux-command/

		Disable rlogind
		https://www.cyberciti.biz/faq/linux-disable-rlogind-rlogind-server-linux-command/

		Disable rlogin
		https://www.cyberciti.biz/faq/linux-disable-rlogin-rlogin-server-linux-command/

		Limit failed login attempts
		https://www.cyberciti.biz/faq/linux-limit-failed-login-attempts-linux-command/

		Generate audit records for certain commands
		https://www.cyberciti.biz/faq/linux-audit-records-for-certain-commands-linux-command/




	*/

}


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

func accessRootLogin() {
	// access.conf
	_, err := exec.Command("echo", "+:root:192.168.89.1", ">>", "/etc/security/access.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
}

func identifyPackageManager() {
	supportedPackMan := []string{"apt", "yum", "pacman"}
	for i:=0; i<len(supportedPackMan);i++ {
		out, err := exec.Command("which", supportedPackMan[i]).Output()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(string(out))
			//_, err = exec.Command("sudo", supportedPackMan[i], "install", "fail2ban").Output()
			//_, err = exec.Command("sudo", supportedPackMan[i], "install", "auditd", "audispd-plugins").Output()
		}
	}
}

func setTcpSynCookies() {
	_, err := exec.Command("sudo", "echo", "'net.ipv4.tcp_syncookies = 1'", ">>", "/etc/sysctl.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("sudo", "sysctl", "-p").Output()
	if err != nil {
		fmt.Println(err)
	}
}

func disableIPv6() {
	_, err := exec.Command("sudo", "echo", "'net.ipv6.conf.all.disable_ipv6 = 1'", ">>", "/etc/sysctl.conf").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("sudo", "sysctl", "-p").Output()
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

func findSUIDSGIDBits() {
	cmd := "sudo find / -type f \\( -perm -04000 -o -perm -02000 \\)")
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(out))
}
