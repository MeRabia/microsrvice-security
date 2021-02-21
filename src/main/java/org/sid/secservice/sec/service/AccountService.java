package org.sid.secservice.sec.service;

import org.sid.secservice.sec.entities.AppRole;
import org.sid.secservice.sec.entities.AppUser;

import java.util.List;

public interface AccountService  {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username , String roleName);
    //cette methode va vers la bd et chercher le username et le recuperer
    AppUser loadUserByUserName(String username);
    List<AppUser> listUsers();
}
