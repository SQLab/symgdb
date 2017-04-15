import Vue from 'vue'
import Vuex from 'vuex'
import VueResource from 'vue-resource'
import App from './App.vue'

Vue.use(VueResource)
Vue.use(VueResource)

new Vue({
  el: '#app',
  render: (h) => h(App),
  created: function () {
  },
  methods: {
    updateTrace: function (id) {
      Vue.http.get('/traces/' + id).then((response) => {
        this.assembly = response.body.assemblys
        this.register = response.body.registers
      }, (response) => {
      })
    }
  }
})

// Connect to websocket server
const host = window.location.host
const ws = new WebSocket('ws://' + host + '/ws')

ws.onopen = function () {
  console.log('Connected to server')
}

ws.onmessage = function (message) {
  console.log(message.data)
}

ws.onclose = function () {
  console.log('Disconnected from server')
}

ws.onerror = function (error) {
  console.log(error)
}
console.log('test')

