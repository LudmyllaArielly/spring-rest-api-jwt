package ludmylla.api.rest.security;

import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import ludmylla.api.rest.ApplicationContextLoad;
import ludmylla.api.rest.model.Usuario;
import ludmylla.api.rest.repository.UsuarioRepository;

@Service
@Component
public class JWTTokenAutenticacaoService {
	
	/** Classe que gera o token e também valida do token enviado **/
	
	/* Tempo de validade do token 2 dias */
	private static final long EXPIRATION_TIME = 172800000;
	
	/* Uma senha única para compor a autenticação e ajudar na segurança */
	private static final String SECRET = "secretomaximo";
	
	/* Prefixo padrão de Token */
	private static final String TOKEN_PREFIX = "Bearer";
	
	private static final String HEADER_STRING = "Authorization";
	
	/* Gerando token de autenticação e adicionando o cabeçalho e resposta Http */
	public void addAuthentication(HttpServletResponse response, String username) throws IOException {
		
		/* Montagem do Token */
		String JWT = Jwts.builder() /* Chama o gerador de token */
				.setSubject(username)/* Adiciona o usuário */
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) /* Tempo de expiração */
				.signWith(SignatureAlgorithm.HS512, SECRET).compact(); /* Compactação e algoritmo de geração de senha */
		
		/* Junta o token com o prefixo */
		String token = TOKEN_PREFIX + " " + JWT; /* Bearer JASMDSAIDS52D4F5GG41 Ex */
		
		/* Adiciona no cabeçalho http */
		response.addHeader(HEADER_STRING, token); /* Authorization:Bearer JASMDSAIDS52D4F5GG41 */
		
		
		/* Escreve token como resposta no corpo http */
		response.getWriter().write("{\"Authorization\":\""+token+"\"}");
		
		//Liberando resposta para portas diferentes que usam a api ou caso clientes web
		liberacaoCors(response);
		
		/*
		if(response.getHeader("Access-Control-Allow-Origin") == null) {
			response.addHeader("Access-Control-Allow-Origin", "*");
		}*/
		
	}
	
	/* Retorna o usuário validado com token ou caso  não seja válido retorna null */
	public Authentication getAuthentication(HttpServletRequest request, HttpServletResponse response) {
		
		/* Pega o token enviado no cabeçalho http */
		String token = request.getHeader(HEADER_STRING);
		
		try {
			
			if(token != null) {
				
				String tokenLimpo = token.replace(TOKEN_PREFIX, "").trim();
						
				/* Faz a validação do token do usuário na requisição */
				String user = Jwts.parser().setSigningKey(SECRET) /* Bearer JASMDSAIDS52D4F5GG41 */
						.parseClaimsJws(tokenLimpo) /* JASMDSAIDS52D4F5GG41 */
						.getBody().getSubject(); /* Ex: João Silva*/
				
				if(user != null) {
					Usuario usuario = ApplicationContextLoad
							.getApplicationContext()
							.getBean(UsuarioRepository.class).findUserByLogin(user);
					
					/* Retorna o usuário logado */
					if(usuario != null) {
						
						if(tokenLimpo.equalsIgnoreCase(usuario.getToken())) {
						
							return new UsernamePasswordAuthenticationToken(
										usuario.getLogin(), 
										usuario.getSenha(), 
										usuario.getAuthorities());
						}
							
					}
				}
		
			}/* Fim da condição token*/
		
		}catch (io.jsonwebtoken.ExpiredJwtException e) {
			try {
				response.getOutputStream().println(
						"Seu TOKEN está expirado, faça o login ou informe um novo TOKEN para autenticação!");
			
			} catch (IOException e1) {
				
			}
		}
		
		liberacaoCors(response);
		
		/*if(response.getHeader("Access-Control-Allow-Origin") == null) {
			response.addHeader("Access-Control-Allow-Origin", "*");
		}*/
		
	
		
		return null; /* Não Autorizado */

	}

	private void liberacaoCors(HttpServletResponse response) {
		
		if(response.getHeader("Access-Control-Allow-Origin") == null) {
			response.addHeader("Access-Control-Allow-Origin", "*");
		}
		
		if(response.getHeader("Access-Control-Allow-Headers") == null) {
			response.addHeader("Access-Control-Allow-Headers", "*");			
		}
		
		if(response.getHeader("Access-Control-Request-Headers") == null) {
			response.addHeader("Access-Control-Request-Headers", "*");
			
		}
		
		if(response.getHeader("Access-Control-Allow-Methods") == null) {
			response.addHeader("Access-Control-Allow-Methods", "*");
		}
		
	}
	
	
	
}
