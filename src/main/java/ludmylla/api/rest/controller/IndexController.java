package ludmylla.api.rest.controller;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ludmylla.api.rest.model.Usuario;
import ludmylla.api.rest.model.UsuarioDTO;
import ludmylla.api.rest.repository.UsuarioRepository;

@CrossOrigin(origins = "http://localhost:4200", allowedHeaders = "*")
@RestController // Arquitetura REST
@RequestMapping(value = "/usuario")
public class IndexController {
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	
	@GetMapping(value = "/{id}/codigovenda/{venda}", produces = "application/json")
	public ResponseEntity<Usuario> relatorio(@PathVariable(value = "id") Long id,
			@PathVariable(value = "venda") Long venda) {	
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		
		/* Retorno seria um relatorio */
		
		return new ResponseEntity<Usuario>(usuario.get(), HttpStatus.OK);
	}
	
	
	/* Serviço RESTfull */
	// Usando UsuarioDTO
	@GetMapping(value = "/{id}", produces = "application/json")
	public ResponseEntity<UsuarioDTO> init(@PathVariable(value = "id") Long id) {	
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		System.out.println("Versão 1");
		return new ResponseEntity<UsuarioDTO>(new UsuarioDTO(usuario.get()), HttpStatus.OK);
	}
	
	/* Serviço RESTfull */
	@GetMapping(value = "/{id}", produces = "application/json", headers = "X-API-Version=v2")
	public ResponseEntity<Usuario> initV2(@PathVariable(value = "id") Long id) {	
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		System.out.println("Versão 2");
		return new ResponseEntity<Usuario>(usuario.get(), HttpStatus.OK);
	}
	
	// Vamos supor que o carregamento do usuário seja um processo lento
	// então vamos controlar com cache para agilizar
	@GetMapping(value = "/", produces = "application/json")
	@CacheEvict(value = "cacheListUsuario", allEntries = true)
	@CachePut("cacheListUsuario") /* Indetifica se tem atualizações*/
	public ResponseEntity<List<Usuario>> usuario() throws InterruptedException{
		
		List<Usuario> list = (List<Usuario>) usuarioRepository.findAll();
		//Thread.sleep(6000); /*Segura o codigo por + seg simulando um processo lento*/
		
		return new ResponseEntity<List<Usuario>>(list, HttpStatus.OK);
	}
	
	//End-point são metodos finais da api, listar, cadastrar
	//@CrossOrigin(origins = {"www.sistemadocliente10.com.br","www.sistemadocliente30.com.br"})
	@PostMapping(value = "/", produces = "application/json")
	public ResponseEntity<Usuario> cadastrar(@RequestBody Usuario usuario){
		
		// Na hora de salvar, automaticamente vamos pegar o telefones e relacionar ao usuario
		
		for (int pos = 0; pos < usuario.getTelefones().size(); pos++) {
			usuario.getTelefones().get(pos).setUsuario(usuario);
		}
		
		// Exemplo de fazer o for usando expressao lambdas
		// usuario.getTelefones().forEach(t -> t.setUsuario(usuario));
	
		String senhaCriptografada = new BCryptPasswordEncoder().encode(usuario.getSenha());
		usuario.setSenha(senhaCriptografada);
		Usuario usuarioSalvo = usuarioRepository.save(usuario);
		return new ResponseEntity<Usuario>(usuarioSalvo, HttpStatus.OK);
		
	}
	
	@PostMapping(value = "/{iduser}/idvenda/{idvenda}", produces = "application/json")
	public ResponseEntity<Usuario> cadastrarVenda(@PathVariable Long iduser, @PathVariable Long idvenda){
		
		//Usuario usuarioSalvo = usuarioRepository.save(usuario);
		return new ResponseEntity("id user: " + iduser+ " id venda: " +idvenda, HttpStatus.OK);
		
	}
	//@CrossOrigin(origins = "localhost:8080")
	@PutMapping(value = "/", produces = "application/json")
	public ResponseEntity<Usuario> atualizar(@RequestBody Usuario usuario){
		
		for (int pos = 0; pos < usuario.getTelefones().size(); pos++) {
			usuario.getTelefones().get(pos).setUsuario(usuario);
		}
		
		Usuario userTemporario = usuarioRepository.findUserByLogin(usuario.getLogin());
		
		if(!userTemporario.getSenha().equals(usuario.getSenha())) { /* Senha diferentes */
			
			String senhaCriptografada = new BCryptPasswordEncoder().encode(usuario.getSenha());
			usuario.setSenha(senhaCriptografada);	
		}

		Usuario usuarioUpdate = usuarioRepository.save(usuario);
		return new ResponseEntity<Usuario>(usuarioUpdate, HttpStatus.OK);
		
	}
	
	
	@DeleteMapping(value = "/{id}/venda", produces = "application/text")
	public String deleteVenda(@PathVariable("id") Long id) {
		
		usuarioRepository.deleteById(id);
		
		return "ok";
	}
	
	
	@DeleteMapping(value = "/{id}", produces = "application/text")
	public String delete(@PathVariable("id") Long id) {
		
		usuarioRepository.deleteById(id);
		
		return "ok";
	}
	


}
