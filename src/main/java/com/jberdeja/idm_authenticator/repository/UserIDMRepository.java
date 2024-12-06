package com.jberdeja.idm_authenticator.repository;

import java.math.BigInteger;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import com.jberdeja.idm_authenticator.entityes.UserIDMEntity;

@Repository
public interface UserIDMRepository extends CrudRepository<UserIDMEntity, BigInteger>{
    Optional<UserIDMEntity> findByEmail(String email);
}
