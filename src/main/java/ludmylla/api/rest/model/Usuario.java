package ludmylla.api.rest.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ConstraintMode;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.UniqueConstraint;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
public class Usuario implements UserDetails{

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	
	private String nome;
	
	@Column(unique = true)
	private String login;
	private String senha;
	
	@OneToMany(mappedBy = "usuario", orphanRemoval = true, fetch = FetchType.LAZY, cascade = CascadeType.ALL)
	private List<Telefone> telefones = new ArrayList<Telefone>();
	//private Set<Telefone> telefones = new HashSet<Telefone>();
	
	@OneToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "usuarios_role", 
			  uniqueConstraints = @UniqueConstraint(
					  columnNames = {"usuario_id", "role_id"}, 
					  name = "unique_role_user"),
	joinColumns = @JoinColumn(name = "usuario_id", 
						     referencedColumnName = "id",
						     table = "usuario",
						     unique = false,
	foreignKey = @ForeignKey(name = "usuario_fk", value = ConstraintMode.CONSTRAINT)),
	
	inverseJoinColumns = @JoinColumn(name = "role_id",
	                                referencedColumnName = "id",	                       
	                                table = "role", 
	                                unique = false,
	                                updatable = false,
	foreignKey = @ForeignKey(name = "role_fk", value = ConstraintMode.CONSTRAINT)))
	private List<Role> roles; /* Lista de acessos, papeis um usuário pode ter muitos papéis */
	
	private String token = "";
	
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getNome() {
		return nome;
	}
	public void setNome(String nome) {
		this.nome = nome;
	}
	public String getLogin() {
		return login;
	}
	public void setLogin(String login) {
		this.login = login;
	}

	public String getSenha() {
		return senha;
	}
	
	public void setSenha(String senha) {
		this.senha = senha;
	}
	
	public List<Telefone> getTelefones() {
		return telefones;
	}
	
	public void setTelefones(List<Telefone> telefones) {
		this.telefones = telefones;
	}
	
	public String getToken() {
		return token;
	}
	
	public void setToken(String token) {
		this.token = token;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Usuario other = (Usuario) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Usuario [id=" + id + ", nome=" + nome + ", login=" + login + ", senha=" + senha + ", telefones="
				+ telefones + ", roles=" + roles + ", token=" + token + "]";
	}
	
	/* São os acessos do usuário ROLE_ADMIN..*/
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {		
		return roles;
	}
	
	@JsonIgnore
	@Override
	public String getPassword() {
		return this.senha;
	}
	
	@JsonIgnore
	@Override
	public String getUsername() {
		return this.login;
	}
	//Restringir os dados do usuário
	@JsonIgnore
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	
	@JsonIgnore
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	
	@JsonIgnore
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	@JsonIgnore
	@Override
	public boolean isEnabled() {
		return true;
	}
	
}
