// Поганий приклад
val n = 100
def calc(a: Int, b : Int) : Int = a + b

// Гарний приклад
val maxConnections = 100
def calculateSum(firstNumber : Int, secondNumber : Int) : Int = firstNumber + secondNumber

// Поганий приклад
val discount = 0.2 // Знижка дорівнює 0.2

// Гарний приклад
val discountRate = 0.2 // Знижка для користувачів зі статусом "Premium"

// Поганий приклад
def add(a:Int, b : Int) :Int = { a + b }println(add(5, 10))

// Гарний приклад
def add(a : Int, b : Int) : Int = {
  a + b
}

println(add(5, 10))

// Поганий приклад
def processOrder(order: Order) : Unit = {
  println(s"Order ID: ${order.id}")
  println(s"Total Price: ${order.totalPrice}")
  println("Sending email notification...")
  sendEmail(order.customerEmail, "Order Processed")
}

// Гарний приклад
def processOrder(order: Order) : Unit = {
  logOrderDetails(order)
  sendOrderNotification(order)
}

def logOrderDetails(order : Order) : Unit = {
  println(s"Order ID: ${order.id}")
  println(s"Total Price: ${order.totalPrice}")
}

def sendOrderNotification(order : Order) : Unit = {
  val message = createEmailMessage(order)
  sendEmail(order.customerEmail, message)
}

// Поганий приклад
def doWork(a: Int, b : Int) : Int = a * b

// Гарний приклад
def calculateProduct(multiplier : Int, multiplicand : Int) : Int = multiplier * multiplicand

// Поганий приклад
def getUser(id : Int) : User = fetchUserFromDB(id)
def saveOrder(order : Order) : Boolean = println("Order saved")

// Гарний приклад
def getUser(id : Int) : Option[User] = fetchUserFromDB(id)
def saveOrder(order : Order) : Unit = saveOrderToDB(order)

// Поганий приклад
def multiply(a:Int,b:Int):Int = {
   a+b
}

// Гарний приклад
def multiply(a : Int, b : Int) : Int = {
  a + b
}

// Поганий приклад
def checkAmount(amount: Int) : String =
  if (amount > 100) return "High value"
  else return "Low value"

// Гарний приклад
def checkAmount(amount : Int) : String = {
  if (amount > 100) {
    return "High value"
  } else {
    return "Low value"
  }
}

// Поганий приклад
val isEligible = age > 18 && income > 30000 && creditScore > 700

// Гарний приклад
val isEligible = age > 18 &&
                 income > 30000 &&
                 creditScore > 700

// Приклад коду до застосування рекомендацій
def main(args: Array[String]) : Unit = {
  val x = 100; val y = 50; if (x > y)println("Valid")else println("Invalid")
  def tax(a:Int,b : Int) = a * b * 0.1
  println(tax(100,200))
  def tstatus(s:String) = if (s == "ok")true else false
  println(tstatus("ok"))
  def getuser(id:Int) = println(s"User ID: $id")
  getuser(5)
}

// Приклад коду після застосування рекомендацій
def calculateTax(amount: Int, rate : Int) : Double = {
  amount * rate * 0.1
}

def checkTransactionStatus(status : String) : Boolean = {
  if (status == "ok") {
	true
  } else {
	false
  }       
}

def fetchUserData(userId: Int) : Unit = {
  println(s"Fetching data for User ID: $userId")
}

def main(args : Array[String]) : Unit = {
val totalAmount = 100
val taxRate = 200
val calculatedTax = calculateTax(totalAmount, taxRate)
println(s"Calculated Tax: $calculatedTax")

val transactionStatus = "ok"
val isTransactionValid = checkTransactionStatus(transactionStatus)
println(s"Transaction Valid: $isTransactionValid")

 val userId = 5
fetchUserData(userId)

if (
  totalAmount > taxRate &&
  taxRate > 0
) {
  println("Tax rate is valid")
} else {
  println("Invalid tax rate")
}
        
