const { gql } = require("apollo-server");

module.exports = gql` 
  type Post {
    id: ID!
    body: String!
    name: String!
    createdAt: String!

  }

  type User{
      id: ID!,
      email: String!
      token: String!
      name: String!
      createdAt: String!
  }
  input RegisterInput{
      name: String!
      password: String! 
      confirmPassword: String! 
      email: String!
  }

  type Query {
    getPosts: [Post]
  }

  type Mutation{
      register(registerInput : RegisterInput): User!
      login(email: String!, password: String!): User!
  }
`;
