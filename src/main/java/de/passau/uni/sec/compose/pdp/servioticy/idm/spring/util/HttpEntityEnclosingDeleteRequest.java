package de.passau.uni.sec.compose.pdp.servioticy.idm.spring.util;

import java.net.URI;

import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;

public class HttpEntityEnclosingDeleteRequest extends HttpEntityEnclosingRequestBase{

    public HttpEntityEnclosingDeleteRequest(final URI uri) {
           super();
           setURI(uri);
       }
    
       @Override
       public String getMethod() {
           return "DELETE";
       }
}