package com.bisht.springsecurityjdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // THis will tell which type of authentication needed (InMemory,JDBC,LDAP,OAuth,etc). This is for JDBC
        // as we have H2 embedded database spring will automatically create the datasource for H2.

        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(User.withUsername("user").password("user").roles("USER"))
                .withUser(User.withUsername("admin").password("admin").roles("ADMIN"));

        /*
        In the above statement H2 has actually a default schema to make for the security name and passwords table.
        We can have a different schema for the table of our choice also.So we have just use the default schema
        and had made the users and passwords. So at run time the spring will add the record to this embedded database.
        */
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/").permitAll()
                .and()
                .formLogin();
    }

    @Bean
    public PasswordEncoder getPassword() {
        return NoOpPasswordEncoder.getInstance();
    }
}
