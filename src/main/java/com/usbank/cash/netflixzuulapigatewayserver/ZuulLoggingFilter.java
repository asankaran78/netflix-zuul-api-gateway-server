package com.usbank.cash.netflixzuulapigatewayserver;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


@Component
public class ZuulLoggingFilter extends ZuulFilter {
	

    public static final String AUTHORIZATION_HEADER = "Authorization";
    
    private long EXPIRATIONTIME = 1000 * 60 * 5; 
    private String secret = "ThisIsASecret";

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() throws ZuulException {
		
		createAndAttachJwtToken(RequestContext.getCurrentContext());	
		return null;
	
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 1;
	}
	
	private void createAndAttachJwtToken(RequestContext context) {
		
        HttpServletRequest request = context.getRequest();
        String userName = request.getHeader("username");

        String authorizationHeader = Jwts.builder()
                 .setSubject(userName)
                 .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                 .signWith(SignatureAlgorithm.HS512, secret)
                 .compact();
    
        context.addZuulRequestHeader(AUTHORIZATION_HEADER, authorizationHeader);
    }

}
