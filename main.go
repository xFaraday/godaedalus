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
		Disable core dumps
		https://www.cyberciti.biz/faq/disable-core-dumps-linux/
		https://www.cyberciti.biz/faq/how-to-disable-core-dumps-in-linux/

		Edit access.conf to allow root login from a specific subnet
		https://www.cyberciti.biz/faq/how-to-allow-root-login-from-a-specific-subnet/

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

		Install auditd
		https://www.cyberciti.biz/faq/linux-auditd-linux-audit-daemon/

		set net.ipv4.tcp_syncookies to 1
		https://www.cyberciti.biz/faq/linux-kernel-tcp-syncookies-linux-command/

		disable ipv6 net.ipv6.conf.all.disable_ipv6 = 1
		https://www.cyberciti.biz/faq/linux-kernel-ipv6-disable-ipv6-linux-command/

		Disable wack http methods for apache
		https://www.cyberciti.biz/faq/linux-apache-disable-http-methods-apache-command/

		For SSH stuff:
		check permissions for /etc/ssh/ stuff
		https://dev-sec.io/baselines/ssh/

		import baseline secure sshd config file and overwrite sshd_config file in place

		check for blank passwords:
		https://www.cyberciti.biz/faq/linux-check-for-blank-passwords-linux-command/

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
