package com.authorization.crewservice.services;

import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class CustomUserPermissionEvaluator implements UserPermissionEvaluator {
    @Override
    public void requireManage() {

    }

    @Override
    public void requireManage(UserModel userModel) {

    }

    @Override
    public boolean canManage() {
        return false;
    }

    @Override
    public boolean canManage(UserModel userModel) {
        return false;
    }

    @Override
    public void requireQuery() {

    }

    @Override
    public boolean canQuery() {
        return false;
    }

    @Override
    public void requireView() {

    }

    @Override
    public void requireView(UserModel userModel) {

    }

    @Override
    public boolean canView() {
        return false;
    }

    @Override
    public boolean canView(UserModel userModel) {
        return false;
    }

    @Override
    public void requireImpersonate(UserModel userModel) {

    }

    @Override
    public boolean canImpersonate() {
        return false;
    }

    @Override
    public boolean canImpersonate(UserModel userModel) {
        return false;
    }

    @Override
    public boolean isImpersonatable(UserModel userModel) {
        return false;
    }

    @Override
    public Map<String, Boolean> getAccess(UserModel userModel) {
        return null;
    }

    @Override
    public void requireMapRoles(UserModel userModel) {

    }

    @Override
    public boolean canMapRoles(UserModel userModel) {
        return false;
    }

    @Override
    public void requireManageGroupMembership(UserModel userModel) {

    }

    @Override
    public boolean canManageGroupMembership(UserModel userModel) {
        return false;
    }

    @Override
    public void grantIfNoPermission(boolean b) {

    }
}
