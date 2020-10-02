package ludmylla.api.rest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import ludmylla.api.rest.service.ImplementacaoUserDetailsService;

/* Mapeia url, endereços, autoriza ou bloqueia acessos a urls */
@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter{
	
	/** Mapeia toda parte de segurança e registra a classes de token **/
	
	
	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;
	
	/* Configura as solicitações de acesso por HTTP */
	@Override
		protected void configure(HttpSecurity http) throws Exception {			
		
		
		/*Ativando a proteção contra usuários que não estão validados por token */
		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		
		/* Ativando a permissão para acesso a página inicial do sistema Ex: sistema.com.br/index.html */
		.disable()
		.cors()
		.and()
		.authorizeRequests().antMatchers("/").permitAll()
		.antMatchers("/index").permitAll()		

		//Liberando fazer leitura get, post, put vários opções de uso da api
		.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
		
		/*URL de logout - Redireciona após o user deslogar do sistema */
		.anyRequest().authenticated().and().logout().logoutSuccessUrl("/index")
		
		/* Mapeia URL de Logout e invalida o usuário */
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		
		/* Filtra as requisões de login para autenticação */
		.and().addFilterBefore(new JWTLoginFilter(
				"/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)

		/* Filtra demais requisões para verificar a presença do TOKEN JWT no HEADER HTTP */
		.addFilterBefore(new JWTApiAutenticacaoFilter(),
				UsernamePasswordAuthenticationFilter.class);
		
		
		
		/*
		http.csrf()
		.disable()
		.cors()
		.and()
		.authorizeRequests()
		.antMatchers(HttpMethod.POST, "/login").permitAll()
		.anyRequest().authenticated()
		.and().logout()
		.and()
		.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
				UsernamePasswordAuthenticationFilter.class)
		.addFilterBefore(new JWTApiAutenticacaoFilter(), 
				UsernamePasswordAuthenticationFilter.class)
		;*/
	}
			
		
	
	
	
	@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			/* Service que irá consultar o usuário no banco de dados */
			auth.userDetailsService(implementacaoUserDetailsService)
			/* Padrão de codificação de senha */
			.passwordEncoder(new BCryptPasswordEncoder());		
			
		}
}
