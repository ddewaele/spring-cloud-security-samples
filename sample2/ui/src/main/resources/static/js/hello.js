angular.module('hello', [ 'ngRoute' ]).config(function($routeProvider) {

	$routeProvider.when('/', {
		templateUrl : 'home.html',
		controller : 'home',
		controllerAs : 'controller'
	}).otherwise('/');

}).controller('navigation',

function($rootScope, $http, $location, $route) {

	var self = this;

	self.tab = function(route) {
		return $route.current && route === $route.current.controller;
	};

	$http.get('/user').success(function(data) {
		if (data.username) {
			$rootScope.authenticated = true;
		} else {
			$rootScope.authenticated = false;
		}
	}).error(function() {
		$rootScope.authenticated = false;
	});

	self.credentials = {};

	self.logout = function() {
		$http.post('logout', {}).finally(function() {
			$rootScope.authenticated = false;
			$location.path("/");
		});
	}

}).controller('home', function($http) {
	var self = this;
	$http.get('/resource1/').success(function(data) {
		self.resource1 = data;
	})
	$http.get('/resource2/').success(function(data) {
		self.resource2 = data;
	})
	$http.get('/user/').success(function(data) {
		self.user= data;
	})

	$http.get('/ui//uiservice/managerService').success(function(data) {
		self.managerService= data;
	}).error(function(data) {
		self.managerService = data;
	});

	$http.get('/ui//uiservice/adminService').success(function(data) {
		self.adminService= data;
	}).error(function(data) {
		self.adminService = data;
	});

	$http.get('/ui/uiservice/userService').success(function(data) {
		self.userService= data;
	}).error(function(data) {
		self.userService = data;
	});

	$http.get('/ui/uiservice/publicService').success(function(data) {
		self.publicService= data;
	}).error(function(data) {
		self.publicService = data;
	});

	$http.get('/ui/uiservice/authenticatedService').success(function(data) {
		self.authenticatedService= data;
	}).error(function(data) {
		self.authenticatedService = data;
	});


});
