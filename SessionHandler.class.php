<?php

/**
 * Class SessionHandler
 *
 * @author         METANET <entwicklung@metanet.ch>
 * @copyright      Copyright (c) 2014, METANET AG
 */

namespace classes\session;

class SessionHandler {

	private $started;
	private $savePath;
	private $name;
	private $remoteAddress;
	private $userAgent;
	private $ID;

	public function __construct($savePath = null, $name = null, $remoteAddress = null, $userAgent = null) {
		$this->started = false;
		$this->ID = null;

		$this->savePath = $savePath;
		$this->name = $name;
		$this->remoteAddress = $remoteAddress;
		$this->userAgent = $userAgent;
	}

	public function start() {

		// is session handling already started?
		if($this->started === true) {
			return;
		}

		// set session_save_path
		if($this->savePath !== null) {
			session_save_path($this->savePath);
		}

		if($this->name !== null) {
			$sn = $this->name;

			// overwrite session id in cookie when provided by get-Parameter
			if(isset($_GET[$sn]) && isset($_COOKIE[$sn]) && $_COOKIE[$sn] !== $_GET[$sn]) {
				$_COOKIE[$sn] = $_GET[$sn];
				session_id($_GET[$sn]);
			}

			// set session_name
			session_name($sn);
		}

		// start session handling
		if(session_start() === false) {
			throw new SessionException('Could not start session');
		}

		// security check: prevent from session hijacking
		$ra = $this->remoteAddress;
		$ua = $this->userAgent;

		if(
			!isset($_SESSION['TRUSTED_REMOTE_ADDR'])
			|| $_SESSION['TRUSTED_REMOTE_ADDR'] !== $ra
			|| !isset($_SESSION['PREV_USERAGENT'])
			|| $_SESSION['PREV_USERAGENT'] !== $ua
		) {
			$this->regenerateID();
		}

		// set started to true
		$this->started = true;
	}

	public function getID() {
		if($this->ID === null) {
			$this->ID = session_id();
		}

		return $this->ID;
	}

	public function getName() {
		if($this->name === null) {
			$this->name = session_name();
		}

		return $this->name;
	}

	public function regenerateID() {
		if(!isset($_SESSION['TRUSTED_SID']) && session_id() !== '') {
			session_destroy();
			session_start();
		}

		session_regenerate_id();
		$this->ID = session_id();

		$_SESSION['TRUSTED_SID'] = true;
		$_SESSION['TRUSTED_REMOTE_ADDR'] = $this->remoteAddress;
		$_SESSION['PREV_USERAGENT'] = $this->userAgent;
	}

	public function close() {
		if($this->started === true)
			session_write_close();
	}

}

/* EOF */
