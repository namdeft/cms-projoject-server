// import {User} from '../models';
// import {UserRepository} from '../repositories';
import {authenticate, TokenService} from '@loopback/authentication';
import {
    Credentials,
    MyUserService,
    TokenServiceBindings,
    User,
    UserRepository,
    UserServiceBindings,
} from '@loopback/authentication-jwt';
import {inject} from '@loopback/core';
import {
    Count,
    CountSchema,
    Filter,
    FilterExcludingWhere,
    model,
    property,
    repository,
    Where,
} from '@loopback/repository';
import {
    del,
    get,
    getModelSchemaRef,
    param,
    patch,
    post,
    put,
    requestBody,
    response,
    SchemaObject,
} from '@loopback/rest';
import {SecurityBindings, securityId, UserProfile} from '@loopback/security';
import {genSalt, hash} from 'bcryptjs';
import _ from 'lodash';

const CredentialsSchema: SchemaObject = {
    type: 'object',
    required: ['email', 'password'],
    properties: {
        email: {
            type: 'string',
            format: 'email',
        },
        password: {
            type: 'string',
            minLength: 6,
        },
    },
};

@model()
export class NewUserRequest extends User {
    @property({
        type: 'string',
        required: true,
    })
    password: string;
}

export const CredentialsRequestBody = {
    description: 'The input of login function',
    required: true,
    content: {
        'application/json': {schema: CredentialsSchema},
    },
};

export class UserController {
    constructor(
        @inject(TokenServiceBindings.TOKEN_SERVICE)
        public jwtService: TokenService,
        @inject(UserServiceBindings.USER_SERVICE)
        public userService: MyUserService,
        @inject(SecurityBindings.USER, {optional: true})
        public user: UserProfile,
        @repository(UserRepository)
        public userRepository: UserRepository,
    ) {}

    @post('/users/login', {
        responses: {
            '200': {
                description: 'Token',
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                token: {
                                    type: 'string',
                                },
                            },
                        },
                    },
                },
            },
        },
    })
    async login(@requestBody(CredentialsRequestBody) credentials: Credentials) {
        const user = await this.userService.verifyCredentials(credentials);

        const userProfile = this.userService.convertToUserProfile(user);

        const token = await this.jwtService.generateToken(userProfile);

        const {username, email, id} = user;

        return {
            token,
            username,
            email,
            id,
        };
    }

    @authenticate('jwt')
    @get('/whoAmI', {
        responses: {
            '200': {
                description: 'Return current user',
                content: {
                    'application/json': {
                        schema: {
                            type: 'string',
                        },
                    },
                },
            },
        },
    })
    async whoAmI(
        @inject(SecurityBindings.USER)
        currentUserProfile: UserProfile,
    ): Promise<string> {
        return currentUserProfile[securityId];
    }

    @get('/users/count')
    @response(200, {
        description: 'User model count',
        content: {'application/json': {schema: CountSchema}},
    })
    async count(@param.where(User) where?: Where<User>): Promise<Count> {
        return this.userRepository.count(where);
    }

    @post('/signup', {
        responses: {
            '200': {
                description: 'User',
                content: {
                    'application/json': {
                        schema: {
                            'x-ts-type': User,
                        },
                    },
                },
            },
        },
    })
    async signUp(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(NewUserRequest, {
                        title: 'NewUser',
                    }),
                },
            },
        })
        newUserRequest: NewUserRequest,
    ): Promise<User> {
        const password = await hash(newUserRequest.password, await genSalt());
        const savedUser = await this.userRepository.create(_.omit(newUserRequest, 'password'));

        await this.userRepository.userCredentials(savedUser.id).create({password});

        return savedUser;
    }

    @get('/users')
    @response(200, {
        description: 'Array of User model instances',
        content: {
            'application/json': {
                schema: {
                    type: 'array',
                    items: getModelSchemaRef(User, {includeRelations: true}),
                },
            },
        },
    })
    async find(@param.filter(User) filter?: Filter<User>): Promise<User[]> {
        return this.userRepository.find(filter);
    }

    @post('/users')
    @response(200, {
        description: 'User model instance',
        content: {'application/json': {schema: getModelSchemaRef(User)}},
    })
    async create(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(User, {
                        title: 'NewUser',
                        exclude: ['id'],
                    }),
                },
            },
        })
        user: Omit<User, 'id'>,
    ): Promise<User> {
        return this.userRepository.create(user);
    }

    @patch('/users')
    @response(200, {
        description: 'User PATCH success count',
        content: {'application/json': {schema: CountSchema}},
    })
    async updateAll(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(User, {partial: true}),
                },
            },
        })
        user: User,
        @param.where(User) where?: Where<User>,
    ): Promise<Count> {
        return this.userRepository.updateAll(user, where);
    }

    @get('/users/{id}')
    @response(200, {
        description: 'User model instance',
        content: {
            'application/json': {
                schema: getModelSchemaRef(User, {includeRelations: true}),
            },
        },
    })
    async findById(
        @param.path.string('id') id: string,
        @param.filter(User, {exclude: 'where'}) filter?: FilterExcludingWhere<User>,
    ): Promise<User> {
        return this.userRepository.findById(id, filter);
    }

    @patch('/users/{id}')
    @response(204, {
        description: 'User PATCH success',
    })
    async updateById(
        @param.path.string('id') id: string,
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(User, {partial: true}),
                },
            },
        })
        user: User,
    ): Promise<void> {
        await this.userRepository.updateById(id, user);
    }

    @put('/users/{id}')
    @response(204, {
        description: 'User PUT success',
    })
    async replaceById(
        @param.path.string('id') id: string,
        @requestBody() user: User,
    ): Promise<void> {
        await this.userRepository.replaceById(id, user);
    }

    @del('/users/{id}')
    @response(204, {
        description: 'User DELETE success',
    })
    async deleteById(@param.path.string('id') id: string): Promise<void> {
        await this.userRepository.deleteById(id);
    }
}
