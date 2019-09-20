<?php
/**
 * Mail library
 *
 * @author Eko Junaidi Salam <eko_junaidisalam@live.com>
 */

date_default_timezone_set('Asia/Jakarta');
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once('vendor/autoload.php');

class EJS_Mail{
	const SMTP_HOST = 'mail.ekojunaidisalam.com';
	
	private static $instance = null;
	
	public $smtp_host;
	public $email_account;
	public $to;
	public $cc;
	public $bcc;
	public $subject;
	public $body;
	public $altbody;
	
    private final function __construct() {
        $this->smtp_host = EJS_Mail::SMTP_HOST;
        $this->email_account = array('ekojs@ekojunaidisalam.com','Eko Junaidi Salam');
        $this->cc = null;
        $this->bcc = null;
    }
	
	private final function __clone(){ }
	
    public final function __sleep(){
        throw new Exception('Serializing of Singletons is not allowed');
    }
	
    public static function getInstance(){
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }
	
	public function setFrom($account=null){
		$this->email_account = (!empty($account)?$account:$this->email_account);
		return $this;
	}
	
	public function setTo($to=null){
		$this->to = (!empty($to)?$to:null);
		return $this;
	}
	
	public function setCC($cc=null){
		$this->cc = (!empty($cc)?$cc:null);
		return $this;
	}
	
	public function setBCC($bcc=null){
		$this->bcc = (!empty($bcc)?$bcc:null);
		return $this;
	}
	
	public function setSubject($subject=null){
		$this->subject = (!empty($subject)?$subject:null);
		return $this;
	}
	
	public function setBody($body=null){
		$this->body = (!empty($body)?$body:null);
		return $this;
	}
	
	public function setAltBody($altbody=null){
		$this->altbody = (!empty($altbody)?$altbody:null);
		return $this;
	}
	
	public function send($password=null){
		if(empty($password)) trigger_error("Password is invalid !!!",E_USER_ERROR);
		if(empty($this->email_account)) trigger_error("Email is invalid !!!",E_USER_ERROR);
		if(empty($this->to)) trigger_error("Email recipients is invalid !!!",E_USER_ERROR);
		if(empty($this->subject)) trigger_error("Subject is invalid !!!",E_USER_ERROR);
		if(empty($this->body)) trigger_error("Body is invalid !!!",E_USER_ERROR);
		
		$receipts = array();
		$mail = new PHPMailer(true);
		try{
			$mail->SMTPOptions = array(
				'ssl' => array(
						'verify_peer' => false,
						'verify_peer_name' => false,
						'allow_self_signed' => true
				)
			);
			$mail->SMTPDebug = 1;                       // Enable verbose debug output
			$mail->isSMTP();                            // Set mailer to use SMTP
			$mail->Host = $this->smtp_host;  		      // Specify main and backup SMTP servers
			$mail->SMTPAuth = true;                     // Enable SMTP authentication
			$mail->Username = $this->email_account[0];     // SMTP username
			$mail->Password = base64_decode($password);                       // SMTP password
			$mail->SMTPSecure = 'tls';                  // Enable TLS encryption, `ssl` also accepted
			$mail->Port = 587;                          // TCP port to connect to
			
			$mail->setFrom($this->email_account[0], $this->email_account[1]);
			if(!empty($this->to)){
				$to = explode(",",$this->to);
				if(is_array($to)){
					foreach($to as $rcpt){
						$mail->addAddress($rcpt);
					}
				}else{
					$mail->addAddress($to);
				}
			}
			
			if(!empty($this->cc)){
				$cc = explode(",",$this->cc);
				if(is_array($cc)){
					foreach($cc as $rcpt){
						$mail->addCC($rcpt);
					}
				}else{
					$mail->addCC($cc);
				}
			}
			
			if(!empty($this->bcc)){
				$bcc = explode(",",$this->bcc);
				if(is_array($bcc)){
					foreach($bcc as $rcpt){
						$mail->addBCC($rcpt);
					}
				}else{
					$mail->addBCC($bcc);
				}
			}
			
			$mail->isHTML(true);                                  // Set email format to HTML
			$mail->Subject = $this->subject;
			$mail->Body    = $this->body;
			$mail->AltBody = $this->altbody;
			
			$mail->send();
			printf("[+] Message has been sent to %s\n\n",(is_array($this->to)?implode(",",$this->to):$this->to));
		}catch(Exception $e){
			printf("[!] Message could not be sent. Mailer Error: %s\n\n", $mail->ErrorInfo);
		}
	}
}