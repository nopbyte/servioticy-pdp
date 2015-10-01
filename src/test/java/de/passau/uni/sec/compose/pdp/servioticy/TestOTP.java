package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import iotp.model.GenericSenderOTPData;
import iotp.model.ISenderOTPData;
import iotp.model.communication.DataReceiver;
import iotp.model.communication.DataSender;
import iotp.model.exception.IOTPException;
import iotp.model.storage.StorageProviderFactory;
import iotp.model.storage.model.EncodedUser;
import iotp.model.utils.Utils;
import iotp.service.otp.Cipher;
import iotp.service.otp.SecretDerivatorFactory;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class TestOTP
{
	String url = "http://localhost:8080/private/security/";
	
	@Test
	public void TestSendAndReceiveSmall() throws IOTPException, JsonProcessingException, IOException
	{
		PDP pdp = new LocalPDP();
		pdp.setServioticyPrivateHost(url);
		Map<String,Object> iotpParams = new HashMap<String,Object>();
		iotpParams.put("servioticy.url.otp", "info");
		iotpParams.put("servioticy.private.url", url);
		
		
		byte[] key = iotp.service.otp.Cipher.generateKey(256);
		GenericSenderOTPData data = new GenericSenderOTPData();
		data.setMaxHeight(-1);
		data.setSecretDerivationType(SecretDerivatorFactory.RIGHT_BIT_SHIFT_IDENTITY);
		data.setMaxWidth(16);
		data.setFactorOfSecretDerivation(8);
		data.setIndex(0);
		data.setDepth(0);
		data.setRootSecret(key);
		EncodedUser u = new EncodedUser();
		u.setId("1");
		data.setInfo(u);
		try
		{
			DataReceiver dr = new DataReceiver(StorageProviderFactory.PROVIDER_SERVIOTICY, iotpParams);
			dr.addNewOTPSenderData(data.getRootSecret(), data);// this stores the next OTP in servioticy updated automattically....
			
			GenericSenderOTPData data2 = new GenericSenderOTPData();
			data2.setMaxHeight(-1);
			data2.setMaxWidth(16);
			data2.setFactorOfSecretDerivation(8);
			data2.setIndex(0);
			data2.setDepth(0);
			data2.setRootSecret(key);
			data2.setInfo(u);
			DataSender ds = new DataSender(data2);
			int i = 0;
			while(i++<40){
				byte [] r = ds.encryptMessage(Utils.binaryFromUTF8String("{\"someProperty\":3}"));
				try
				{
					pdp.GenericSendDatatoServiceObjectProv("SHA-256:LBS:8", generateSecurityMetadata("soid", "a"), null, null, "a", Utils.fromBinaryToHexString(r));
				} catch (PDPServioticyException e)
				{
					assertTrue(false);
					e.printStackTrace();
				}
			}
	
		
		} catch (IOTPException e)
		{
			e.printStackTrace();
			assertTrue(false);
		}
	}
	
	@Test
	public void TestSendAndReceiveSmallWrong() throws IOTPException, JsonProcessingException, IOException
	{
		
		PDP pdp = new LocalPDP();
		pdp.setServioticyPrivateHost(url);
		Map<String,Object> iotpParams = new HashMap<String,Object>();
		iotpParams.put("servioticy.url.otp", "info");
		iotpParams.put("servioticy.private.url", url);
		
		
		byte[] key = iotp.service.otp.Cipher.generateKey(256);
		GenericSenderOTPData data = new GenericSenderOTPData();
		data.setMaxHeight(-1);
		data.setSecretDerivationType(SecretDerivatorFactory.RIGHT_BIT_SHIFT_IDENTITY);
		data.setMaxWidth(16);
		data.setFactorOfSecretDerivation(8);
		data.setIndex(0);
		data.setDepth(0);
		data.setRootSecret(key);
		EncodedUser u = new EncodedUser();
		u.setId("-1");
		data.setInfo(u);
		try
		{
			DataReceiver dr = new DataReceiver(StorageProviderFactory.PROVIDER_SERVIOTICY, iotpParams);
			dr.addNewOTPSenderData(data.getRootSecret(), data);// this stores the next OTP in servioticy updated automattically....
			
			GenericSenderOTPData data2 = new GenericSenderOTPData();
			data2.setMaxHeight(-1);
			data2.setMaxWidth(16);
			data2.setFactorOfSecretDerivation(8);
			data2.setIndex(0);
			data2.setDepth(0);
			data2.setRootSecret(key);
			data2.setInfo(u);
			DataSender ds = new DataSender(data2);
			int i = 0;
			while(i++<40){
				byte [] r = ds.encryptMessage(Utils.binaryFromUTF8String("{\"someProperty\":3}"));
				try
				{
					pdp.GenericSendDatatoServiceObjectProv("SHA-256:LBS:8", generateSecurityMetadata("soid", "a"), null, null, "a", Utils.fromBinaryToHexString(r));
				} catch (PDPServioticyException e)
				{
					e.printStackTrace();
					assertTrue(e.getStatus() == 403);
				}
			}
	
		
		} catch (IOTPException e)
		{
			e.printStackTrace();
			assertTrue(false);
		}
	}

	 private JsonNode generateSecurityMetadata(String soid, String streamid) throws JsonProcessingException, IOException
	 {
		String template = "{ \"id\":\"d\", \"owner_id\":\"asdf\", \"flows\":[]}";
		return new ObjectMapper().readTree(template);
	 }
}
