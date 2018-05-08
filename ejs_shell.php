<?php
/**
	AppName : EJS Shell Script
	Version : 1.0
	Author	: Eko Junaidi Salam <eko_junaidisalam@live.com>
**/

defined('AUTHOR') OR define('AUTHOR', "ejs");
defined('HOSTNAME') OR define('HOSTNAME', "shell");
$back = false;
$exit = false;

defined('USER') OR define('USER', "user");
defined('TOKEN') OR define('TOKEN', "tokenmu");
defined('ENDPOINT') OR define('ENDPOINT', "urlmu");
defined('CRT') OR define('CRT', "");
defined('CRT_KEY') OR define('CRT_KEY', "");
defined('CA_BUNDLE') OR define('CA_BUNDLE', "");

if($argc > 1){
	if('whm' === $argv[1] && 'createacct' === $argv[2]){
		if(!empty($argv[3]) && !empty($argv[4]) && !empty($argv[5])){
			if(!empty($argv[3]) && '-y' === $argv[3]){
				$param[0] = $argv[4];
				$param[1] = $argv[5];
				$param[2] = $argv[6];
				$param[3] = $argv[3];
			}else{
				$param[0] = $argv[3];
				$param[1] = $argv[4];
				$param[2] = $argv[5];
			}
			whm_create(ENDPOINT,USER,TOKEN,$argv[2],$param);
		}else{
			print "[!] Creating invalid account, please read this specs !!!\n";
			help_whm('createacct');
			print "[-] Add option '-y' without quotes to force yes every confirm.\n";
			print "[-] Usage: php $argv[0] whm createacct -y broeko book.ekojunaidisalam.com ekojs@ekojunaidisalam.com \n\n";
		}
	}else if('whm' === $argv[1] && 'installssl' === $argv[2]){
		if(!empty($argv[3]) && !empty($argv[4])){
			if(!empty($argv[3]) && '-y' === $argv[3]){
				$param[0] = $argv[4];
				$param[1] = $argv[5];
				$param[2] = $argv[3];
			}else{
				$param[0] = $argv[3];
				$param[1] = $argv[4];
			}
			whm_install_ssl(ENDPOINT,USER,TOKEN,$argv[2],$param);
		}else{
			print "[!] Installing invalid ssl, please read this specs !!!\n";
			help_whm('installssl');
			print "[-] Add option '-y' without quotes to force yes every confirm.\n";
			print "[-] Usage: php $argv[0] whm installssl -y book.ekojunaidisalam.com 104.27.185.116 \n\n";
		}
	}else{
		print "|****************************************************************|\n";
		print "                         EJS Shell Code                           \n";
		print "    Credit: Eko Junaidi Salam , eko_junaidisalam@live.com         \n";
		print "                    Welcome to EJS Shell Code                     \n";
		print "|****************************************************************|\n";
		print "\n";
		print "Usage: php $argv[0] \n";
	}
	exit;
}

	print "|****************************************************************|\n";
	print "                         EJS Shell Code                           \n";
	print "    Credit: Eko Junaidi Salam , eko_junaidisalam@live.com         \n";
	print "                    Welcome to EJS Shell Code                     \n";
	print "|****************************************************************|\n";
	print "\n";
	print "[-] Hello, what do you want ? \n";
	banner();
	
    while(!$exit){
		$back = false;
		fwrite(STDOUT, "\n[ ".AUTHOR."@".HOSTNAME." ~] > ");
		$read = trim(fgets(STDIN));
		
		if("exit" === $read) $exit = true;
		
		switch($read){
			case 'help':
				banner();
				break;
			case 'shell':
				printf("\n\n[-] You choose Command Shell\n");
				while(!$back){
					fwrite(STDOUT, "[ ".AUTHOR."@".HOSTNAME." ~] shell > ");
					$read = trim(fgets(STDIN));
					if('exit' === $read){
						exit;
					}else if('back' === $read){
						$back = true;
					}else{
						$res = execute($read);
						printf("[+] Result: %s\n",$res);
					}
					
				}
				break;
			case 'ipinfo':
				printf("\n\n[-] You choose IP Info\n");
				while(!$back){
					fwrite(STDOUT, "[ ".AUTHOR."@".HOSTNAME." ~] ipinfo > ");
					$read = trim(fgets(STDIN));
					if('exit' === $read){
						exit;
					}else if('back' === $read){
						$back = true;
					}else{
						printf("[-] ipinfo: '%s'\n",$read);
						
						$site = @htmlentities($read);
						if (empty($site)){
							printf("[!] %s is invalid...\n",$site);
							exit;
						}
						ipinfo($site);
					}
				}
				break;
			case 'whm':
				printf("\n\n[-] You choose WHM\n");
				while(!$back){
					fwrite(STDOUT, "[ ".AUTHOR."@".HOSTNAME." ~] whm > ");
					$read = trim(fgets(STDIN));
					
					switch($read){
						case 'exit':
							exit;
							break;
						case 'back':
							$back = true;
							break;
						case 'help':
							help_whm();
							break;
						case 'createacct':
							$backwhm = false;
							help_whm('createacct');
							
							while(!$backwhm){
								fwrite(STDOUT, "[ ".AUTHOR."@".HOSTNAME." ~] whm createacct > ");
								$par = trim(fgets(STDIN));
								$param = explode(' ',$par);
								
								switch($par){
									case 'exit':
										exit;
										break;
									case 'back':
										$backwhm = true;
										break;
									case 'help':
										help_whm('createacct');
										break;
									default:
										whm_create(ENDPOINT,USER,TOKEN,$read,$param);
										break;
								}
							}
							break;
						case 'installssl':
							$backwhm = false;
							help_whm('installssl');
							
							while(!$backwhm){
								fwrite(STDOUT, "[ ".AUTHOR."@".HOSTNAME." ~] whm installssl > ");
								$par = trim(fgets(STDIN));
								$param = explode(' ',$par);
								
								switch($par){
									case 'exit':
										exit;
										break;
									case 'back':
										$backwhm = true;
										break;
									case 'help':
										help_whm('installssl');
										break;
									default:
										whm_install_ssl(ENDPOINT,USER,TOKEN,$read,$param);
										break;
								}
							}
							break;
						default:
							whm_list(ENDPOINT,USER,TOKEN,$read);
							break;
					}
				}
				break;
		}
	}
	exit;
	
function banner(){
	print "[-] Action you can take : \n";
	print "[x] shell \t- Command Shell \n";	
	print "[x] ipinfo \t- IP Information \n";
	help_whm();
}
	
function help_whm($cmd='none'){
	switch($cmd){
		case 'createacct':
			printf("\n\n[-] Fill in account parameter to create a CPANEL account.\n");
			printf("[-] Specs : \n\tDelimiter \t: <space> \n\tUsername \t: Username length is more than 5 less then 16 \n\tDomain \t\t: Must be subdomain of *.ekojunaidisalam.com \n\tEmail \t\t: Must have '@' character \n");
			printf("[-] Data example, ex : username domain contactemail \n\tbroeko book.ekojunaidisalam.com ekojs@ekojunaidisalam.com\n\n");
			break;
		case 'installssl':
			printf("\n\n[-] Fill in ssl parameter to install ssl.\n");
			printf("[-] Data example, ex : domain ip \n\tbook.ekojunaidisalam.com 104.27.185.116\n\n");
			printf("[-] Specs : \n\tDelimiter \t: <space> \n\tDomain \t\t: Must be subdomain of *.ekojunaidisalam.com \n\tIP \t\t: Must be IPv4 specs or 'n' without quotes for default \n");
			break;
		default:
			print "[-] Action you can take : \n";
			print "[x] whm \t- WHM Functions \n";
			print "\t[x] createacct \t- Create Account CPANEL \n";
			print "\t[x] installssl \t- Install SSL for CPANEL \n";
			print "\t[x] listaccts \t- List Account in WHM \n";
			print "\t[x] listpkgs \t- List Packages in WHM \n";
			print "\t[x] listcrts \t- List Certificates in WHM \n";
			print "\t[x] fetch_ssl_vhosts \t- List Vhosts Certificates in WHM \n";
			break;
	}
}
	
function execute($cmd){
	if(function_exists('system')){
		@ob_start();
		@system($cmd);
		$buff = @ob_get_contents();
		@ob_end_clean();
		return $buff;
	}else if(function_exists('exec')){
		@exec($cmd,$results);
		$buff = "";
		foreach($results as $result) $buff .= $result;
		return $buff;
	}else if(function_exists('passthru')){
		@ob_start();
		@passthru($cmd);
		$buff = @ob_get_contents();
		@ob_end_clean();
		return $buff;
	}else if(function_exists('shell_exec')){
		$buff = @shell_exec($cmd);
		return $buff;
	} 
}

function ipinfo($site){
	@set_time_limit(0);
	@error_reporting(0);
	$ip = @gethostbyname($site);
	printf("[-] Checking %s ip %s ... \n",$site,$ip);
	
	$curl = curl_init();
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);
    curl_setopt($curl, CURLOPT_URL, "https://ipinfo.io/".$ip);

    $result = curl_exec($curl);
	
	$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    if ($http_status != 200) {
        print "[!] Error: " . $http_status . " returned\n";
    } else {
        print "[+] Results :\n";
		print_r($result);
		print "\n";
    }
    curl_close($curl);
}

function whm_list($endpoint,$user,$token,$cmd){
	if(empty($cmd)) exit("[!] Command invalid !!!\n");
	
	$curl = curl_init();
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);

    $header[0] = "Authorization: whm $user:$token";
    curl_setopt($curl,CURLOPT_HTTPHEADER,$header);
    curl_setopt($curl, CURLOPT_URL, $endpoint.$cmd."?api.version=1");

    $result = curl_exec($curl);

    $http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    if ($http_status != 200) {
        print "[!] Error: " . $http_status . " returned\n";
    } else {
        $json = json_decode($result);
		switch($cmd){
			case 'listaccts':
				print "[+] Current cPanel users on the system:\n";
				foreach ($json->{'data'}->{'acct'} as $userdetails) {
					print "\t [+] " . $userdetails->{'user'}.(strlen($userdetails->user) < 11?"\t\t\t":(strlen($userdetails->user) >= 11 && strlen($userdetails->user) < 16?"\t\t":"\t\t")). ": ". $userdetails->domain .($userdetails->suspended == 1?" ( Suspended )":null)."\n";
				}
				print "Total Account : ". count($json->data->acct)."\n";
				break;
			case 'listpkgs':
				print "[+] Current packages on the system:\n";
				foreach ($json->{'data'}->{'pkg'} as $pkg) {
					printf("\t [+] %s : \n\t\tCGI -> %s,\n\t\tMax Addon -> %s,\n\t\tBandwith Limit -> %s,\n\t\tFeature List -> %s,\n\t\tMax POP -> %s,\n\t\tMax SQL -> %s,\n\t\tDigest Auth -> %s,\n\t\tCP Mod -> %s,\n\t\tShell -> %s,\n\t\tMax FTP -> %s,\n\t\tMax Subdomain -> %s,\n\t\tIP -> %s,\n\t\tQuota -> %s,\n\t\tMax Park -> %s \n",$pkg->name,$pkg->CGI,$pkg->MAXADDON,$pkg->BWLIMIT,$pkg->BWLIMIT,$pkg->FEATURELIST,$pkg->MAXPOP,$pkg->MAXSQL,$pkg->DIGESTAUTH,$pkg->MAXLST,$pkg->CPMOD,$pkg->HASSHELL,$pkg->MAXFTP,$pkg->MAXSUB,$pkg->IP,$pkg->QUOTA,$pkg->MAXPARK);
				}
				print "Total Packages : ". count($json->data->pkg)."\n";
				break;
			case 'listcrts':
				print "[+] Current certificates on the system:\n";
				foreach ($json->data->crt as $crt) {
					printf("\t [+] %s : \n\t\tFriendly Name -> %s,\n\t\tIssuer -> %s,\n\t\tID -> %s,\n\t\tRegistered -> %s \n",$crt->domain,$crt->friendly_name,$crt->{'issuer.organizationName'},$crt->id,$crt->registered);
				}
				print "Total Certificates : ". count($json->data->crt)."\n";
				break;
			case 'fetch_ssl_vhosts':
				print "[+] Current certificates on the system:\n";
				$i = 1;
				foreach ($json->data->vhosts as $vhosts) {
					printf("\t [%d] %s : \n\t\tUser -> %s,\n\t\tIP -> %s,\n\t\tIP Type -> %s,\n\t\tCertificate -> %s \n",$i,$vhosts->servername,$vhosts->user,$vhosts->ip,$vhosts->iptype,$vhosts->crt->{'issuer.organizationName'});
					printf("\t\t\tID -> %s,\n\t\t\tCommon Name -> %s,\n\t\t\tSelf Signed -> %s \n",$vhosts->crt->id,$vhosts->crt->{'subject.commonName'}->commonName,$vhosts->crt->is_self_signed);
					$i++;
				}
				print "Total Vhosts Certificates : ". count($json->data->vhosts)."\n";
				break;
			default:
				print "[!] Command invalid...\n";
				break;
		}
    }
    curl_close($curl);
}

function whm_create($endpoint,$user,$token,$cmd,$param){
	if(empty($cmd)) print "[!] Command invalid !!!\n";
	if(!is_array($param) && count($param) != 3) print "[!] Parameter invalid !!!\n";
	
	if(strlen($param[0]) <= 5 || strlen($param[0]) >= 16){
		print "[!] Parameter username invalid...\n";
	}else if(!preg_match_all('/(?<domain>[a-z\-\.]+\.ekojunaidisalam\.com)/', $param[1], $domain, PREG_SET_ORDER, 0)){
		print "[!] Parameter domain invalid...\n";
	}else if(!preg_match_all('/(?<email>[\w\.\_\-]+\@[\w\.\_\-]+)/', $param[2], $email, PREG_SET_ORDER, 0)){
		print "[!] Parameter email invalid...\n";
	}else{
		$param[1] = $domain[0]['domain'];
		$param[2] = $email[0]['email'];
		
		if(empty($param[3]) || '-y' !== $param[3]){
			printf("[-] Are you sure to create this account : \n\tUsername \t: %s\n\tDomain \t\t: %s\n\tEmail \t\t: %s \n(y/n)? ",$param[0],$param[1],$param[2]);
		}
		$y = (!empty($param[3]) && '-y' === $param[3]?'y':trim(fgets(STDIN)));
		if('y' === strtolower($y)){
			$username = $param[0];
			$domain = $param[1];
			$email = $param[2];
			
			$curl = curl_init();
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);

			$header[0] = "Authorization: whm $user:$token";
			curl_setopt($curl,CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_URL, $endpoint.$cmd."?api.version=1");
			curl_setopt($curl, CURLOPT_POST, TRUE);
			curl_setopt($curl, CURLOPT_POSTFIELDS, array(
				"username" => $username,
				"domain" => $domain,
				"password" => "password",
				"contactemail" => $email,
				"hasshell" => 0,
				"plan" => "plan"
			));

			$result = curl_exec($curl);

			$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			if ($http_status != 200) {
				print "[!] Error: " . $http_status . " returned\n";
			} else {
				$json = json_decode($result);
				if(!empty($json->data)){
					print "[+] Account Created\n";
					print "[+] Timestamps ".date('d-m-Y H:i:s')."\n";
					print "[+] ".$domain." ".$json->metadata->reason."\n";
					print "[+] IP : ".$json->data->ip."\n";
					print "[+] Package : ".$json->data->package."\n\n";
				}else{
					print "[!] Result : ".$result."\n\n";
				}
			}
			curl_close($curl);
		}
	}
}

function whm_install_ssl($endpoint,$user,$token,$cmd,$param){
	if(empty($cmd)) print "[!] Command invalid !!!\n";
	if(!is_array($param) || count($param) > 3) print "[!] Parameter invalid !!!\n";
	
	if(!preg_match_all('/^(?<ip>(?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$|n)/', $param[1], $ips, PREG_SET_ORDER, 0)){
		print "[!] Parameter ip invalid...\n";
	}
	
	if(!preg_match_all('/(?<domain>[a-z\-\.]+\.ekojunaidisalam\.com)/', $param[0], $domain, PREG_SET_ORDER, 0)){
		print "[!] Parameter domain invalid...\n";
	}
	
	if(!empty($domain[0]['domain']) && !empty($ips[0]['ip'])){
		$param[0] = $domain[0]['domain'];
		$param[1] = ("n" === $ips[0]['ip']?"104.27.185.116":$ips[0]['ip']);
		
		if(empty($param[2]) || '-y' !== $param[2]){
			printf("[-] Are you sure to install ssl for this account : \n\tDomain \t\t: %s\n\tIP \t\t: %s \n(y/n)? ",$param[0],$param[1]);
		}
		$y = (!empty($param[2]) && '-y' === $param[2]?'y':trim(fgets(STDIN)));
		if('y' === strtolower($y)){
			$domain = $param[0];
			$ip = $param[1];
			
			$curl = curl_init();
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);

			$header[0] = "Authorization: whm $user:$token";
			curl_setopt($curl,CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_URL, $endpoint.$cmd."?api.version=1");
			curl_setopt($curl, CURLOPT_POST, TRUE);
			curl_setopt($curl, CURLOPT_POSTFIELDS, array(
				"domain" => $domain,
				"ip" => $ip,
				"crt" => CRT,
				"key" => CRT_KEY,
				"cab" => CA_BUNDLE
			));

			$result = curl_exec($curl);

			$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			if ($http_status != 200) {
				print "[!] Error: " . $http_status . " returned\n";
			} else {
				$json = json_decode($result);
				if(!empty($json->data)){
					print "[+] Timestamps ".date('d-m-Y H:i:s')."\n";
					printf("[+] Domain %s\n",$json->data->domain);
					printf("[+] User %s\n",$json->data->user);
					printf("[+] %s\n\n",$json->data->statusmsg);
				}else{
					print "[!] Result : ".$result."\n\n";
				}
			}
			curl_close($curl);
		}
	}
}

?>