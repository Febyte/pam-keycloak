#include <stdio.h>
#include <string.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char* argv[])
{
    int retval;
    const char* user;
    const char* password;

    // Get the user name
    retval = pam_get_user(pamh, &user, "Username: ");
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    // Get the password
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password: ");
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    return PAM_SUCCESS;
}
