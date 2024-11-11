const Joi = require('joi');
const express = require('express');
const { ValidationError, ServerError } = require('../../errors');
const { checkPassword, encryptPassword } = require('../../helpers/bcrypt');
const { createToken } = require('../../helpers/jwt');
const { authorize } = require('../../middlewares/authorization');
const UserModel = require('../../models/user');
const BaseController = require('../base');
const router = express.Router();

const user = new UserModel();

const signUpSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/)
    .messages({
      'string.min': `Password must be at least {#limit} characters long`,
      'string.pattern.base': `Password must have at least 1 uppercase, 1 lowercase, 1 number, and 1 special character`,
    }),
  fullname: Joi.string(),
});

const signInSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

class AuthController extends BaseController {
  constructor(model) {
    super(model);
  }

  signIn = async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const user = await this.model.getOne({ where: { email } });
      if (!user) return next(new ValidationError('Invalid email or password'));

      const isMatch = await checkPassword(password, user.password);
      if (!isMatch) return next(new ValidationError('Invalid email or password'));

      const token = createToken({ id: user.id });

      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: 'success',
          message: 'Sign in successfully',
          data: {
            user: {
              ...user,
              id: undefined,
              password: undefined,
            },
            token,
          },
        })
      );
    } catch (e) {
      next(new ServerError(e));
    }
  };

  signUp = async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const existingUser = await this.model.getOne({ where: { email } });

      if (existingUser) return next(new ValidationError('Email already exists'));

      const newUser = await this.model.set({
        email,
        password: await encryptPassword(password),
        roleId: 3,
      });

      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: 'success',
          message: 'Sign up successfully',
          data: {
            user: {
              ...newUser,
              id: undefined,
              password: undefined,
            },
          },
        })
      );
    } catch (e) {
      next(new ServerError(e));
    }
  };

  whoAmI = async (req, res, next) => {
    return res.status(200).json(
      this.apiSend({
        code: 200,
        status: 'success',
        message: 'Get user successfully',
        data: {
          user: req.user,
        },
      })
    );
  };
}

const authController = new AuthController(user);

router.post('/signin', authController.validation(signInSchema), authController.signIn);
router.post('/signup', authController.validation(signUpSchema), authController.signUp);
router.get('/whoami', authorize, authController.whoAmI);

module.exports = router;
