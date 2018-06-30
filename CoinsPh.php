<?php
/**
 *
 */
class CoinsPh {
  /**
   * Access Token (OAuth2)
   */
  private $_accessToken;

  /**
   * API Key
   */
  private $_apiKey;

  /**
   * API Secret
   */
  private $_apiSecret;

  /**
   * Authentication identifier
   */
  private $_isHmac;

  /**
   * Request Payment Expiry Date
   */
  private $_requestPaymentExpiryDate = '+1 day';

  /**
   * Request Payment URL
   */
  private $_requestPaymentUrl = 'https://coins.ph/api/v3/payment-requests/';

  /**
   * Crypto Account URL
   */
  private $_cryptoAccountUrl = 'https://coins.ph/api/v3/crypto-accounts/';

  /**
   * Payin Outlets URL
   */
  private $_payinOutletsUrl = 'https://coins.ph/d/api/payin-outlets/';

  /**
   * Constructor
   */
  public function __construct() {}

  /**
   * Set Access Token. For OAuth2 Authentication
   * @param {String} $accessToken
   */
  public function setAccessToken($accessToken) {
    $this->_accessToken = $accessToken;
  }

  /**
   * Initialize instance OAuth2 Authentication type
   */
  public function initOAuth2() {
    if (!$this->_accessToken) die('No Access Token!');
    $this->_isHmac = false;
  }

  /**
   * Initialize instance HMAC Authentication type
   */
  public function initHMAC() {
    $this->_setAPIKeys();
    $this->_isHmac = true;
  }

  /**
   * Get Crypto Account
   * @return {Object}
   */
  public function getCryptoAccounts($currency = 'PBTC,BTC,ETH') {
    return $this->_executeRequest($this->_cryptoAccountUrl, ['currency' => $currency]);
  }

  /**
   * Get Peso Account
   * @return {Object}
   */
  public function getPHPAccount() {
    $response = $this->getCryptoAccounts('PBTC');
    return isset($response->errors) ? false : $response->{'crypto-accounts'}[0];
  }

  /**
   * Get BTC Account
   * @return {Object}
   */
  public function getBTCAccount() {
    $response = $this->getCryptoAccounts('BTC');
    return isset($response->errors) ? false : $response->{'crypto-accounts'}[0];
  }

  /**
   * Get ETH Account
   * @return {Object}
   */
  public function getETHAccount() {
    $response = $this->getCryptoAccounts('ETH');
    return isset($response->errors) ? false : $response->{'crypto-accounts'}[0];
  }

  /**
   * Request Payment
   * @param {String} $payerContactInfo
   * @param {String} $receivingAccount
   * @param {Number} $amount
   * @param {String} $message
   * @return {Object}
   */
  public function requestPayment($payerContactInfo, $receivingAccount, $amount, $message) {
    $datetime = new DateTime();
    $datetime->modify($this->_requestPaymentExpiryDate);
    $expiresAt = $datetime->format('c');
    return $this->_executeRequest($this->_requestPaymentUrl, [
      'payer_contact_info' => $payerContactInfo,
      'receiving_account' => $receivingAccount,
      'amount' => $amount,
      'message' => $message,
      'expires_at' => $expiresAt
    ], 'POST');
  }

  /**
   * Get Payment Request
   * @param {String} $paymentRequestId
   * @param {String} ($status)
   * @return {Object}
   */
  public function getPaymentRequest($paymentRequestId = null, $status = null) {
    $url = !!$paymentRequestId ? $this->_requestPaymentUrl . $paymentRequestId . '/' : $this->_requestPaymentUrl;
    $data = !!$status ? ['status' => $status] : [];
    return $this->_executeRequest($url, $data);
  }

  /**
   * Delete Payment Request
   * @param {String} $paymentRequestId
   */
  public function deletePaymentRequest($paymentRequestId) {
    return $this->_executeRequest($this->_requestPaymentUrl . $paymentRequestId . '/', [], 'DELETE');
  }

  /**
   * Get Payin Outlets
   * @return {Object}
   */
  public function getPayinOutlets() {
    return $this->_executeRequest($this->_payinOutletsUrl, [
      'region' => 'PH',
      'is_enabled' => true
    ]);
  }

  /**
   * Set API Keys
   */
  private function _setAPIKeys() {
    $this->_apiKey = COINSPH_API_KEY;
    $this->_apiSecret = COINSPH_API_SECRET;
  }

  /**
   * Generate nonce
   * @return {Number}
   */
  private function _generateNonce() {
    return intVal(round(microtime(true) * 1000));
  }

  /**
   * Create OAuth2 Request Headers
   * @return {Array}
   */
  private function _createOAuth2RequestHeaders() {
    return [
      'Authorization' => sprintf("Bearer %s", $this->_accessToken),
      'ACCESS_NONCE' => $this->_generateNonce(),
      'Content-Type' => 'application/json;charset=UTF-8',
      'Accept' => 'application/json'
    ];
  }

  /**
   * Create HMAC Request Headers
   * @param {String} $url
   * @param {String} $params
   * @param {String} $method
   * @return {Array}
   */
  private function _createHMACRequestHeaders($url, $params, $method) {
    $nonce = $this->_generateNonce();

    // Format message and body
    if ($method === 'GET' || $method === 'DELETE') {
      $message = sprintf("%d%s", $nonce, $url);
    } else {
      $body = $params;
      $message = sprintf("%d%s%s", $nonce, $url, $body);
    }

    $headers = [
      'ACCESS_SIGNATURE' => hash_hmac('sha256', $message, $this->_apiSecret),
      'ACCESS_KEY' => $this->_apiKey,
      'ACCESS_NONCE' => $nonce,
      'Accept' => 'application/json'
    ];

    if ($method !== 'GET') $headers['Content-Type'] = 'application/json';
    
    return $headers;
  }

  /**
   * Execute Request
   * @param {String} $url
   * @param {String} $params
   * @param {String} $method
   */
  private function _executeRequest($url, $params = [], $method = 'GET') {
    Requests::register_autoloader();

    if ($method === 'GET' && !empty($params)) $url .= '?' . http_build_query($params);

    if ($this->_isHmac) {
      if ($method !== 'GET' || $method !== 'DELETE') $params = json_encode($params);
      $headers = $this->_createHMACRequestHeaders($url, $params, $method);
    } else {
      $headers = $this->_createOAuth2RequestHeaders();
    }

    try {
      if ($method === 'GET') {
        $request = Requests::get($url, $headers);
      } else if ($method === 'DELETE') {
        $request = Requests::delete($url, $headers);
      } else {
        $request = Requests::post($url, $headers, $params);
      }
      return json_decode($request->body);
    } catch (Requests_Exception $e) {
      die($e);
    }
  }
}
