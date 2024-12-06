package com.jberdeja.idm_authenticator.entityes;

import java.util.List;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "roles_idm")
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class RoleIDMEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String roleName;

    private String description;

    @ManyToMany(mappedBy = "roles")
    private List<UserIDMEntity> users;

    public RoleIDMEntity (String roleName, String description){
        this.roleName = roleName;
        this.description = description;
    }
}