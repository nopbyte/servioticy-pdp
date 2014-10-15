package de.passau.uni.sec.compose.pdp.servioticy;

import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public interface PDP 
{
	public enum operationID {//CreateServiceObject,//create a new SO
		UpdateServiceObject,//update a service object definition
		RetrieveServiceObjectDescription,//allows or not retrieval of SO desciption with cache object as a param
		RetrieveServiceObjectStreamsDescription,
		RetrieveServiceObjectData, //checkPermission
		SendDataToServiceObject, //checkAuthorizationWO
		SendDataToServiceObjectProv, //initial provenance
		CreateNewSubscription,
		GetExistingSubscriptionsForStream, 
		DispatchData,//checkAuthorizationDispatch
		GetUserInfo,//returns user id information from acccess_token
		DeleteServiceObjectDescription,//delete a service object
		retrieveSOStreams
	}

	/**
	 * 
	 * @param token access token granted to the user or API_TOKEN given to the web object, depending on the type of the call.
	 * @param security_metadata_SO_current
	 * @param security_metadata_of_the_SU
	 * @param cache
	 * @param opId
	 * @return in general this method returns null. Except when the cache object is used (only in checkPermission)
	 */
	public PermissionCacheObject checkAuthorization(String token, 
			JsonNode  security_metadata_SO_current, 
			JsonNode security_metadata_of_the_SU,
			PermissionCacheObject cache,
			 operationID opId) throws PDPServioticyException;

	public String getIdmHost();
	public void setIdmHost(String idmHost);
	public String getIdmUser();
	public void setIdmUser(String idmUser);
	public String getIdmPassword();
	public void setIdmPassword(String idmPassword);
	public int getIdmPort();
	public void setIdmPort(int idmPort);


}

