package de.passau.uni.sec.compose.pdp.servioticy;
import iotp.model.communication.DataReceiver;
import iotp.model.exception.IOTPException;
import iotp.model.storage.StorageProviderFactory;
import iotp.model.storage.model.DecryptResult;
import iotp.model.storage.model.EncodedUser;
import iotp.model.utils.Utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.authz.AuthorizationServioticy;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IdentityVerifier;
import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;

public class LocalPDP implements PDP
{

	private DataReceiver receiver = null;
	
	private IdentityVerifier id;
	
	private String idmHost;
	
	private int idmPort;
	
	private String idmUser;
	
	private String idmPassword;
	
	private AuthorizationServioticy authz;
	
	private ObjectMapper  mapper;
	
	private String apiUrl;
	
	public LocalPDP()
	{
		id = new IdentityVerifier();
		 authz = new AuthorizationServioticy();
		 mapper = new ObjectMapper();
	}
	
	@Override
	public PermissionCacheObject checkAuthorization(String token,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			operationID opId) throws PDPServioticyException {
		
		if(opId.equals(PDP.operationID.RetrieveServiceObjectData))
		{
		    //TODO SO not used
		    // Check policy (check parameters SU and authentikation token?) do the stuff with the cach object
		    
		    return authz.verifyGetData(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		else if (opId.equals(PDP.operationID.DispatchData)) 
		{
		    // Check policy
		    return authz.verifyGetDataDispatch(security_metadata_SO_current, security_metadata_of_the_SU,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		else if (opId.equals(PDP.operationID.DeleteSensorUpdateData)) 
		{
		    // Check policy
		    return authz.verifyDeleteData(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		
		else if(opId.equals(PDP.operationID.GetUserInfo))
		{
			//returns the user inside cache
			PermissionCacheObject ret = new PermissionCacheObject();
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			String uid = id.userIdFromToken(token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
			tempMapCache.put("UserId", uid);
			ret.setCache(tempMapCache);
			return ret;
		}
		else if(opId.equals(PDP.operationID.RetrieveServiceObjectDescription))
			return authz.retrieveSODescription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.UpdateServiceObject))
			return authz.updateSODescription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.DeleteServiceObjectDescription))
			return authz.deleteSODescription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if (opId.equals(PDP.operationID.retrieveSOStreams))
			return authz.retrieveSOStreams(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.CreateNewSubscription))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.SearchUpdates))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.CreateNewSubscription))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.GetSubscriptions))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.GetSpecificSubscription))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.DeleteSpecificSubscription))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.DispatchPublisher))
			return authz.genericPublicPrivatePolicyNoIDM(security_metadata_of_the_SU, cache);
		else if(opId.equals(PDP.operationID.GetThisSubscriptionInfoForStream))
			return authz.getThisSubscriptionInfoForStream(token,this.idmHost, this.idmUser,this.idmPassword, idmPort, cache);
		else if(opId.equals(PDP.operationID.GetActuations))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.GetActuationStatus))
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.LaunchActuation)) // this one is only getting so because we do policies on the SO only, not in streams or actuators
			return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.UpdateActuation))
			return updateActuationStatus(token, security_metadata_SO_current);
		else {
			throw new PDPServioticyException(501, "The operation is not implemented", "Wrong parameters");			
		}
		
	}

	private PermissionCacheObject updateActuationStatus(String token,
			JsonNode security_metadata_SO_current)
			throws PDPServioticyException {
		//return authz.genericPublicPrivatePolicy(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		id.verifyWebTokenApiToken(security_metadata_SO_current, token);
		//if no exception
		PermissionCacheObject pco = new PermissionCacheObject();
		pco.setPermission(true);
		return pco;
	}

	public IdentityVerifier getId() {
		return id;
	}

	public void setId(IdentityVerifier id) {
		this.id = id;
	}

	public String getIdmHost() {
		return idmHost;
	}

	public void setIdmHost(String idmHost) {
		this.idmHost = idmHost;
	}

	public String getIdmUser() {
		return idmUser;
	}

	public void setIdmUser(String idmUser) {
		this.idmUser = idmUser;
	}

	public String getIdmPassword() {
		return idmPassword;
	}

	public void setIdmPassword(String idmPassword) {
		this.idmPassword = idmPassword;
	}

	public int getIdmPort() {
		return idmPort;
	}

	public void setIdmPort(int idmPort) {
		this.idmPort = idmPort;
	}
	
	
	/**
	 * New call to include decryption.... if the header is SHA-256:LBS:1, Then the content is decrypted, if not the process occurrs as before 
	 * @param token
	 * @param security_metadata_SO_current
	 * @param security_metadata_of_the_SU
	 * @param cache
	 * @param stream
	 * @param data
	 * @return
	 * @throws PDPServioticyException
	 */
	public PermissionCacheObject GenericSendDatatoServiceObjectProv(String token,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String stream,
			String data) throws PDPServioticyException{
		PermissionCacheObject pco = null;
		if(token.trim().toUpperCase().equals("SHA-256:LBS:8"))//hash algorithm, Left bit shift, 8 bits at a time
		{
			pco = new PermissionCacheObject();
			try
			{
				Map<String, Object> tempMapCache = new HashMap<String, Object>();
				DataReceiver dr = getDataReceiver();
				DecryptResult resultObject = dr.decryptMessageAndGetUserData(Utils.fromHexStringToBinary(data));
				String res = new String(resultObject.getDecryptedMessage());
				mapper.readTree(res);
				pco.setDecryptedUpdate(res);
				EncodedUser u = resultObject.getUser();
				if(!authz.evaluatePolicy(u, security_metadata_SO_current, stream))
						throw new PDPServioticyException(403, "user" +u.getId()+" cannot send data to this Service Object", "user" +u.getId()+" cannot send data to this Service Object");
				 try{
					tempMapCache.put("SecurityMetaData", ServioticyProvenance.getInitialProvenance(security_metadata_SO_current, stream));
				} catch (Exception e) {
					throw new PDPServioticyException(400, "The parameters for SendDataToServiceObjectProv were wrong. ", "Wrong parameters");
				    
				}
				pco.setPermission(true);// no exception means everything is OK
				pco.setCache(tempMapCache);
				
			} catch (IOTPException e)
			{
				throw new PDPServioticyException(400, "Problem decrypting data. "+e.getMessage(), "Problem decrypting data. "+e.getMessage()+" debug info: "+e.getDebugMessage());
		
			} catch (JsonProcessingException e)
			{
				throw new PDPServioticyException(400, "Problem decrypting data. Either your data is incorrect or you are not sending the stream JSON object", "Problem decrypting data. Either your data is incorrect or you are not sending the stream JSON object");

			} catch (IOException e)
			{
				throw new PDPServioticyException(400, "Problem decrypting data. I/O exception while parsing JSON (is it JSON actually?)","Problem decrypting data. I/O exception while parsing JSON (is it JSON actually?)");
			}
			
			return pco;
		}
		else{ 
			pco =  SendDataToServiceObjectProv(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, stream);
			pco.setDecryptedUpdate(data);
			return pco;
		}
	}
	
	private  DataReceiver getDataReceiver() throws IOTPException
	{
		if(receiver == null){
			Map<String,Object> iotpParams = new HashMap<String,Object>();
			iotpParams.put("servioticy.url.otp", "info");
			iotpParams.put("servioticy.private.url",this.apiUrl);
			receiver = new DataReceiver(StorageProviderFactory.PROVIDER_SERVIOTICY, iotpParams);
		}
		return receiver;
	}

	public PermissionCacheObject SendDataToServiceObjectProv(String token,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			String stream) throws PDPServioticyException 
			{ 
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			PermissionCacheObject ret = new PermissionCacheObject();			
			
			// Checks the token and returns the security meta-data
			try{
				id.verifyWebTokenApiToken(security_metadata_SO_current, token);
			}
			catch(PDPServioticyException ex)
			{
				//if it was a PDPServioticyException let it flow up!
				throw ex;
			}
			catch(Exception e) {
				throw new PDPServioticyException(400, "Verification of web token error.", "Web token verification error");			    
			}
			// Adds initial provenance
			try{
				tempMapCache.put("SecurityMetaData", ServioticyProvenance.getInitialProvenance(security_metadata_SO_current, stream));
			} catch (Exception e) {
				throw new PDPServioticyException(400, "The parameters for SendDataToServiceObjectProv were wrong. ", "Wrong parameters");
			    
			}
			ret.setCache(tempMapCache);
			return ret;	

	}

	@Override
	public String getServioticyPrivateHost()
	{
		return apiUrl;
		
	}

	@Override
	public void setServioticyPrivateHost(String Host)
	{
		this.apiUrl = Host;
		 
	}
	
	
}
