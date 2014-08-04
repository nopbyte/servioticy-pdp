package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.*;

import org.junit.rules.ExpectedException.*;

import java.io.IOException;
import java.util.UUID;
import java.util.List;
import java.util.LinkedList;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.authz.*;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

import com.jayway.jsonpath.JsonPath;

public class PdpTest 
{
	 private PDP pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
	 }
	
	 @Test
	 public  void simplePdpTest() throws PDPServioticyException
	 {
		 AuthorizationServioticy as = new AuthorizationServioticy();
		 
			String testSO = "{\"security\": {\"policy\": \"public\",\"temperature\": {\"current-value\": 14.04}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSO = new ObjectMapper();
	    JsonNode so_data = null;
		try {
			so_data = mapperSO.readTree(testSO);
		} catch (JsonProcessingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		String testSU = "{\"security\": {\"policy\": \"public\",\"temperature\": {\"current-value\": 14.04}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSU = new ObjectMapper();
	    JsonNode su_data = null;
		try {
			su_data = mapperSU.readTree(testSU);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		 PermissionCacheObject ret = as.verifyGetDataDispatch(so_data, su_data, "", "", "", 0);
		 assertEquals(true, ret.isPermission());		 
	 }
	 
	 
	 @Test
	 public  void noPolicyTest() throws PDPServioticyException
	 {
		 AuthorizationServioticy as = new AuthorizationServioticy();
		 
			String testSO = "{\"security\": {\"policyX\": {\"current-value\": \"38.9833842277,-2.33812933545\"},\"temperature\": {\"current-value\": 14.04}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSO = new ObjectMapper();
	    JsonNode so_data = null;
		try {
			so_data = mapperSO.readTree(testSO);
		} catch (JsonProcessingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		String testSU = "{\"channels\": {\"location\": {\"current-value\": \"38.9833842277,-2.33812933545\"},\"temperature\": {\"current-value\": 14.04}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSU = new ObjectMapper();
	    JsonNode su_data = null;
		try {
			su_data = mapperSU.readTree(testSU);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		 PermissionCacheObject ret = as.verifyGetDataDispatch(so_data, su_data, "", "", "", 0);
		 assertEquals(false, ret.isPermission());		 
	 }
	 
	 @Test
	 public  void privateSameOwner() throws PDPServioticyException
	 {
		 AuthorizationServioticy as = new AuthorizationServioticy();
		 
			String testSO = "{\"security\": {\"policy\": \"private\",\"owner_id\": \"User-A\"},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSO = new ObjectMapper();
	    JsonNode so_data = null;
		try {
			so_data = mapperSO.readTree(testSO);
		} catch (JsonProcessingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		String testSU = "{\"channels\": {\"policy\": \"private\",\"provenance\": {\"onbehalf_of\" : \"User-A\"}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSU = new ObjectMapper();
	    JsonNode su_data = null;
		try {
			su_data = mapperSU.readTree(testSU);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		 PermissionCacheObject ret = as.verifyGetDataDispatch(so_data, su_data, "", "", "", 0);
		 assertEquals(true, ret.isPermission());		 
	 }
	 
	 @Test
	 public  void privateDiffernetOwner() throws PDPServioticyException
	 {
		 AuthorizationServioticy as = new AuthorizationServioticy();
		 
			String testSO = "{\"security\": {\"policy\": \"private\",\"owner_id\": \"User-A\"},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSO = new ObjectMapper();
	    JsonNode so_data = null;
		try {
			so_data = mapperSO.readTree(testSO);
		} catch (JsonProcessingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		String testSU = "{\"channels\": {\"policy\": \"private\",\"provenance\": {\"onbehalf_of\" : \"User-B\"}},\"lastUpdate\": 1399651091}";
	    ObjectMapper mapperSU = new ObjectMapper();
	    JsonNode su_data = null;
		try {
			su_data = mapperSU.readTree(testSU);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		 PermissionCacheObject ret = as.verifyGetDataDispatch(so_data, su_data, "", "", "", 0);
		 assertEquals(false, ret.isPermission());		 
	 }
	 
	 
	 @Test
	 public  void nullTest() throws PDPServioticyException
	 {
		 AuthorizationServioticy as = new AuthorizationServioticy();
		 
		 JsonNode so_data = null;
		 JsonNode su_data = null;

		 PermissionCacheObject ret = as.verifyGetDataDispatch(so_data, su_data, "", "", "", 0);
		 assertEquals(false, ret.isPermission());		 
	 }

}
