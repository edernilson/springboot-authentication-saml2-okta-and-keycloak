package com.edernilson.saml2.config;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements SAMLUserDetailsService {
	
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
	
	public Object loadUserBySAML(SAMLCredential credential)
			throws UsernameNotFoundException {
		
		String userEmail = credential.getNameID().getValue();
		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);

		for (Attribute attribute: credential.getAttributes()) {
			String value = ((XSStringImpl) attribute.getAttributeValues().get(0)).getValue();
			LOG.info(attribute.getName()+": "+value);
		}

		LOG.info(userEmail + " is logged in");

		return new User(userEmail, "", true, true, true, true, authorities);
	}
	
}
