import { check, validationResult } from 'express-validator/check';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import hbs from 'nodemailer-express-handlebars';

import User from '../../models/user';
import allCountries from '../../util/countries';
import config from '../../util/config';
import { smtpTransport, handlebarsOptions } from '../../util/email';

/**
 * Authentication Class
 * 
 * @description this class is responsible for user authentication which includes the following method  
 * @method signUp               - for user registration 
 * @method logIn                - for user login 
 * @method validate             - validates both login and registration forms' data
 * @method passwordResetToken   - sending email with a reset token to a user to reset his password
 * @method passwordResetAttempt - checking if the token is still valid before letting the user submit any new passwords
 * @method passwordResetForm    - accepting the new user password if he followed the link sent to his email address 
 * @method emailActivation      - sends new users activation links to their email addresses
 * @method checkToken           - to validate that users are authentic and can be allowed to visit the desired routes 
 * 
 * @author Omar Abdo
 */
class AuthenticationController {

    signUp(req, res) {
        console.log(req.body);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }
        bcrypt.hash(req.body.password, 10, function (err, hash) {
            User.build({ ...req.body, password: hash })
                .save()
                .then(result => {
                    res.status(200).json({
                        token: jwt.sign({ userId: result.id }, config.privateKey, { expiresIn: 60 * 60 }),
                        success: 'User Created Successfully',
                        authenticated: true,
                    });
                })
                .catch(error => res.status(422).json({ error: error }));
        });
    }

    logIn(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }
        User.findOne({ where: { email: req.body.email } }).then(user => {
            if (user) {
                bcrypt.compare(req.body.password, user.password, function (err, match) {
                    if (match) {
                        res.status(200).json({
                            token: jwt.sign({ userId: res.id }, config.privateKey, { expiresIn: 60 * 60 }),
                            success: 'User Logged In Successfully',
                            authenticated: true,
                        });
                    } else {
                        res.status(422).json({
                            error: 'Email / password is wrong',
                            authenticated: false,
                        });
                    }
                });
            }
        });
    }

    /**
     * @todo try to avoid duplicating the validation code used for the signUp with the login validation
     */
    validate(method) {
        switch (method) {
            case 'signUp': {
                return [
                    check('name').isLength({ min: 4 }).withMessage('name must be longer than 4 characters'),
                    check('name').isLength({ max: 36 }).withMessage('name must be shorter than 36 characters'),
                    check('email').isEmail(),
                    check('email').custom(value => {
                        return User.findOne({ where: { email: value } }).then(user => {
                            if (user) {
                                return Promise.reject('E-mail already exists');
                            }
                        });
                    }),
                    check('password', 'password must be 8+ characters contain at least a number, a capital letter and a special character')
                        .isLength({ min: 8 })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.name) {
                                throw new Error('Passwords can\'t be the same as name ');
                            } else {
                                return value;
                            }
                        })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.email) {
                                throw new Error('Passwords can\'t be the same as email ');
                            } else {
                                return value;
                            }
                        })
                        .matches(/^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/),
                    check('country').custom(value => {
                        if (!allCountries.includes(value)) {
                            throw new Error('Please select a valid country');
                        } else {
                            return value;
                        }

                    }),
                    check('birthday').custom(value => {
                        if (!value || value.length == 0) {
                            throw new Error('You must provide a valid birthday');
                        }
                        if (!value.match(/(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[012])[- /.](19|20)\d\d/)) {
                            throw new Error('Please enter dd/mm/yyyy');
                        }
                        else {
                            return value;
                        }
                    })
                ];
            }
            case 'logIn': {
                return [
                    check('email').isEmail(),
                    check('password', 'password must be 8+ characters contain at least a number, a capital letter and a special character')
                        .isLength({ min: 8 })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.email) {
                                throw new Error('Passwords can\'t be the same as email ');
                            } else {
                                return value;
                            }
                        })
                        .matches(/^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/),
                ];
            }
            case 'passwordResetToken': {
                return [
                    check('email').isEmail(),
                ];
            }
            case 'passwordReset': {
                return [
                    check('password', 'password must be 8+ characters contain at least a number, a capital letter and a special character')
                        .isLength({ min: 8 })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.name) {
                                throw new Error('Passwords can\'t be the same as name ');
                            } else {
                                return value;
                            }
                        })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.email) {
                                throw new Error('Passwords can\'t be the same as email ');
                            } else {
                                return value;
                            }
                        })
                        .matches(/^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/),
                ];
            }

        }
    }

    checkToken(req, res, next) {
        const header = req.headers['authorization'];

        if (typeof header !== 'undefined') {
            req.token = header;
            jwt.verify(req.token, config.privateKey, (err) => {
                if (err) {
                    res.status(403).json({
                        error: "Please Login again 1",
                    });
                } else {
                    next();
                }
            });

        } else {
            res.status(403).json({ error: "Please Login again 2" });
        }
    }

    /**
     * Password Reset Token
     * @description generate the web token needed to reset the password on user request
     * 
     * @todo 5: finally, build an email template that will contain the token in the form of a link or a button and tell the user it expires fast and send it
     * 
     */
    passwordResetToken(req, res, next) {
        if (!req.body.email) {
            res.status(422).json({
                error: 'Email is not provided',
            });
        } else {
            const userEmail = req.body.email;
            User.findOne({ where: { email: userEmail } })
                .then(user => {
                    if (user) {
                        let token = '123'; //generate a better token later
                        user.update({
                            resetToken: token,
                            tokenExpiry: Date.now() + 86400000
                        });
                        //and send an email to the user
                        let data = {
                            //to: user.email, 
                            to: 'me@oabdo.com',
                            from: 'omareabdo@gmail.com',
                            template: 'forgot-password-email',
                            subject: 'Password help has arrived!',
                            context: {
                                url: 'http://localhost:5000/authentication/reset_password?token=' + token, // the url to visit the reset password page
                                name: user.name
                            }
                        };

                        smtpTransport.use('compile', hbs(handlebarsOptions));
                        smtpTransport.sendMail(data, function (err) {
                            if (!err) {
                                res.status(200).json({
                                    success: req.body.email,
                                    token: token,
                                    message: 'Kindly check your email for further instructions'
                                });
                            } else {
                                console.log(err);
                                res.status(422).json({
                                    error: err,
                                });
                            }
                        });
                    } else {
                        res.status(422).json({
                            error: 'This email does not exists. Please sign up first',
                        });
                    }
                })
                .catch(error => {
                    res.status(422).json({
                        error: 'Forbidden Action!',
                    });
                });
        }
    }

    /**
     * Password Rest Attempt
     * @description handles how the user should be navigated after he clicks on the token sent to his email
     * 
     * @todo 1: extract token from the url get req (how to make it open in my flutter app?)
     * @todo 2: if token expired or not provided, send error status token already expired, please ask for a new one
     * @todo 2: otherwise, return 200 success status
     * 
     */
    passwordResetAttempt(req, res, next) {

    }

    /**
     * passwordReset
     * @description allow user to update his password
     * 
     * @todo 1: let the user enter his new password twice showing him which email(account) he is updating 
     * @todo 2: on the put request, recheck if token still valid in time, (cuz what if the user left the reset password screen open for 2 hours before submit)
     * @todo 3: if so, mark it as expired and validate, hash, and update the new password  
     * @todo 4: otherwise, return error status token already expired, please ask for a new one
     */
    passwordReset(req, res, next) {

    }

    /**
     * emailActivation
     * @description allow user to update his password - token doesn't expire or expires in a long time like 7 days
     * 
     * @events on successful signUp or email update, user request for a resend this method should be called
     * 
     * @todo 1: create a token 
     * @todo 2: store the token in DB 
     * @todo 3: send it to user email in a message
     */
    emailActivationToken(req, res, next) {

    }

    /**
     * emailActivation
     * @description allow user to update his password
     * 
     * @todo 3: on user click, get the token and check if it still valid
     * @todo 4: if valid, update the activated field in the user row in the DB to true
     * @todo 3: otherwise, ask the user to get a new token
     */
    emailActivation(req, res, next) {

    }



    /**
     * @todo delete this late
     */
    dummyUser(req, res) {
        console.log(req.body);
        res.status(200).json({
            name: 'John Locke',
            email: 'johnlock@liberalism.com',
            password: '123flutteriscool.com',
            country: 'England',
            birthday: '29/08/1632',
        });
    }

}

const authenticationController = new AuthenticationController();
export default authenticationController;