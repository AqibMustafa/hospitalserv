package com.aqib.hospital.repository;

import com.aqib.hospital.entity.security.AppUser;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RedisRepo {
    private HashOperations hashOperations;

    private RedisTemplate redisTemplate;

    public RedisRepo(RedisTemplate redisTemplate){
        this.redisTemplate = redisTemplate;
        this.hashOperations = this.redisTemplate.opsForHash();
    }

    public void save(String id,String token){
        hashOperations.put("USER", id, token);
    }
    public List findAll(){
        return hashOperations.values("USER");
    }

    public String findById(String id){
        return (String) hashOperations.get("USER", id);
    }

    public void update(String id,String token){
        save(id, token);
    }

    public void delete(String id){
        hashOperations.delete("USER", id);
    }
}
