package de.passau.uni.sec.compose.pdp.servioticy;


public class PDPServioticyException extends Exception
{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4597587636062391283L;
	/**
	 * HTTP error code to be returned
	 */
	private int status;
	/**
	 * End user message (to be forwarded)
	 */
	private String message;
	/**
	 * Detailed information for logging
	 */
	private String logInfo;
	
	
	public PDPServioticyException(int status, String message, String logInfo) {
		super();
		this.status = status;
		this.message = message;
		this.logInfo = logInfo;
	}
	public int getStatus() {
		return status;
	}
	public void setStatus(int status) {
		this.status = status;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getLogInfo() {
		return logInfo;
	}
	public void setLogInfo(String logInfo) {
		this.logInfo = logInfo;
	}
	
	
	
}
